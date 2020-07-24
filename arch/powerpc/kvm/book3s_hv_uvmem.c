// SPDX-License-Identifier: GPL-2.0
/*
 * Secure pages management: Migration of pages between normal and secure
 * memory of KVM guests.
 *
 * Copyright 2018 Bharata B Rao, IBM Corp. <bharata@linux.ibm.com>
 */

/*
 * A pseries guest can be run as secure guest on Ultravisor-enabled
 * POWER platforms. On such platforms, this driver will be used to manage
 * the movement of guest pages between the normal memory managed by
 * hypervisor (HV) and secure memory managed by Ultravisor (UV).
 *
 * The page-in or page-out requests from UV will come to HV as hcalls and
 * HV will call back into UV via ultracalls to satisfy these page requests.
 *
 * Private ZONE_DEVICE memory equal to the amount of secure memory
 * available in the platform for running secure guests is hotplugged.
 * Whenever a page belonging to the guest becomes secure, a page from this
 * private device memory is used to represent and track that secure page
 * on the HV side. Some pages (like virtio buffers, VPA pages etc) are
 * shared between UV and HV. However such pages aren't represented by
 * device private memory and mappings to shared memory exist in both
 * UV and HV page tables.
 */

/*
 * Notes on locking
 *
 * kvm->arch.uvmem_lock is a per-guest lock that prevents concurrent
 * page-in and page-out requests for the same GPA. Concurrent accesses
 * can either come via UV (guest vCPUs requesting for same page)
 * or when HV and guest simultaneously access the same page.
 * This mutex serializes the migration of page from HV(normal) to
 * UV(secure) and vice versa. So the serialization points are around
 * migrate_vma routines and page-in/out routines.
 *
 * Per-guest mutex comes with a cost though. Mainly it serializes the
 * fault path as page-out can occur when HV faults on accessing secure
 * guest pages. Currently UV issues page-in requests for all the guest
 * PFNs one at a time during early boot (UV_ESM uvcall), so this is
 * not a cause for concern. Also currently the number of page-outs caused
 * by HV touching secure pages is very very low. If an when UV supports
 * overcommitting, then we might see concurrent guest driven page-outs.
 *
 * Locking order
 *
 * 1. kvm->srcu - Protects KVM memslots
 * 2. kvm->mm->mmap_sem - find_vma, migrate_vma_pages and helpers, ksm_madvise
 * 3. kvm->arch.uvmem_lock - protects read/writes to uvmem slots thus acting
 *			     as sync-points for page-in/out
 */

/*
 * Notes on page size
 *
 * Currently UV uses 2MB mappings internally, but will issue H_SVM_PAGE_IN
 * and H_SVM_PAGE_OUT hcalls in PAGE_SIZE(64K) granularity. HV tracks
 * secure GPAs at 64K page size and maintains one device PFN for each
 * 64K secure GPA. UV_PAGE_IN and UV_PAGE_OUT calls by HV are also issued
 * for 64K page at a time.
 *
 * HV faulting on secure pages: When HV touches any secure page, it
 * faults and issues a UV_PAGE_OUT request with 64K page size. Currently
 * UV splits and remaps the 2MB page if necessary and copies out the
 * required 64K page contents.
 *
 * Shared pages: Whenever guest shares a secure page, UV will split and
 * remap the 2MB page if required and issue H_SVM_PAGE_IN with 64K page size.
 *
 * HV invalidating a page: When a regular page belonging to secure
 * guest gets unmapped, HV informs UV with UV_PAGE_INVAL of 64K
 * page size. Using 64K page size is correct here because any non-secure
 * page will essentially be of 64K page size. Splitting by UV during sharing
 * and page-out ensures this.
 *
 * Page fault handling: When HV handles page fault of a page belonging
 * to secure guest, it sends that to UV with a 64K UV_PAGE_IN request.
 * Using 64K size is correct here too as UV would have split the 2MB page
 * into 64k mappings and would have done page-outs earlier.
 *
 * In summary, the current secure pages handling code in HV assumes
 * 64K page size and in fact fails any page-in/page-out requests of
 * non-64K size upfront. If and when UV starts supporting multiple
 * page-sizes, we need to break this assumption.
 */

#include <linux/pagemap.h>
#include <linux/migrate.h>
#include <linux/kvm_host.h>
#include <linux/ksm.h>
#include <asm/ultravisor.h>
#include <asm/mman.h>
#include <asm/kvm_ppc.h>

#include <linux/random.h>

static struct dev_pagemap kvmppc_uvmem_pgmap;
static unsigned long *kvmppc_uvmem_bitmap;
static DEFINE_SPINLOCK(kvmppc_uvmem_bitmap_lock);

#define KVMPPC_UVMEM_PFN	(1UL << 63)

struct kvmppc_uvmem_slot {
	struct list_head list;
	unsigned long nr_pfns;
	unsigned long base_pfn;
	unsigned long *pfns;
};

struct kvmppc_uvmem_page_pvt {
	struct kvm *kvm;
	unsigned long gpa;
	bool skip_page_out;
};

bool kvmppc_uvmem_available(void)
{
	/*
	 * If kvmppc_uvmem_bitmap != NULL, then there is an ultravisor
	 * and our data structures have been initialized successfully.
	 */
	return !!kvmppc_uvmem_bitmap;
}

int kvmppc_uvmem_slot_init(struct kvm *kvm, const struct kvm_memory_slot *slot)
{
	struct kvmppc_uvmem_slot *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	p->pfns = vzalloc(array_size(slot->npages, sizeof(*p->pfns)));
	if (!p->pfns) {
		kfree(p);
		return -ENOMEM;
	}
	p->nr_pfns = slot->npages;
	p->base_pfn = slot->base_gfn;

	mutex_lock(&kvm->arch.uvmem_lock);
	list_add(&p->list, &kvm->arch.uvmem_pfns);
	mutex_unlock(&kvm->arch.uvmem_lock);

	return 0;
}

/*
 * All device PFNs are already released by the time we come here.
 */
void kvmppc_uvmem_slot_free(struct kvm *kvm, const struct kvm_memory_slot *slot)
{
	struct kvmppc_uvmem_slot *p, *next;

	mutex_lock(&kvm->arch.uvmem_lock);
	list_for_each_entry_safe(p, next, &kvm->arch.uvmem_pfns, list) {
		if (p->base_pfn == slot->base_gfn) {
			vfree(p->pfns);
			list_del(&p->list);
			kfree(p);
			break;
		}
	}
	mutex_unlock(&kvm->arch.uvmem_lock);
}

static void kvmppc_uvmem_pfn_insert(unsigned long gfn, unsigned long uvmem_pfn,
				    struct kvm *kvm)
{
	struct kvmppc_uvmem_slot *p;

	list_for_each_entry(p, &kvm->arch.uvmem_pfns, list) {
		if (gfn >= p->base_pfn && gfn < p->base_pfn + p->nr_pfns) {
			unsigned long index = gfn - p->base_pfn;

			p->pfns[index] = uvmem_pfn | KVMPPC_UVMEM_PFN;
			return;
		}
	}
}

static void kvmppc_uvmem_pfn_remove(unsigned long gfn, struct kvm *kvm)
{
	struct kvmppc_uvmem_slot *p;

	list_for_each_entry(p, &kvm->arch.uvmem_pfns, list) {
		if (gfn >= p->base_pfn && gfn < p->base_pfn + p->nr_pfns) {
			p->pfns[gfn - p->base_pfn] = 0;
			return;
		}
	}
}

static bool kvmppc_gfn_is_uvmem_pfn(unsigned long gfn, struct kvm *kvm,
				    unsigned long *uvmem_pfn)
{
	struct kvmppc_uvmem_slot *p;

	list_for_each_entry(p, &kvm->arch.uvmem_pfns, list) {
		if (gfn >= p->base_pfn && gfn < p->base_pfn + p->nr_pfns) {
			unsigned long index = gfn - p->base_pfn;

			if (p->pfns[index] & KVMPPC_UVMEM_PFN) {
				if (uvmem_pfn)
					*uvmem_pfn = p->pfns[index] &
						     ~KVMPPC_UVMEM_PFN;
				return true;
			} else
				return false;
		}
	}
	return false;
}

unsigned long kvmppc_h_svm_init_start(struct kvm *kvm)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int ret = H_SUCCESS;
	int srcu_idx;

	kvm->arch.secure_guest = KVMPPC_SECURE_INIT_START;

	if (!kvmppc_uvmem_bitmap)
		return H_UNSUPPORTED;

	/* Only radix guests can be secure guests */
	if (!kvm_is_radix(kvm))
		return H_UNSUPPORTED;

	/* NAK the transition to secure if not enabled */
	if (!kvm->arch.svm_enabled)
		return H_AUTHORITY;

	srcu_idx = srcu_read_lock(&kvm->srcu);
	slots = kvm_memslots(kvm);
	kvm_for_each_memslot(memslot, slots) {
		if (kvmppc_uvmem_slot_init(kvm, memslot)) {
			ret = H_PARAMETER;
			goto out;
		}
		ret = uv_register_mem_slot(kvm->arch.lpid,
					   memslot->base_gfn << PAGE_SHIFT,
					   memslot->npages * PAGE_SIZE,
					   0, memslot->id);
		if (ret < 0) {
			kvmppc_uvmem_slot_free(kvm, memslot);
			ret = H_PARAMETER;
			goto out;
		}
	}
out:
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return ret;
}

unsigned long kvmppc_h_svm_init_done(struct kvm *kvm)
{
	if (!(kvm->arch.secure_guest & KVMPPC_SECURE_INIT_START))
		return H_UNSUPPORTED;

	kvm->arch.secure_guest |= KVMPPC_SECURE_INIT_DONE;
	pr_info("LPID %d went secure\n", kvm->arch.lpid);
	return H_SUCCESS;
}

/*
 * Drop device pages that we maintain for the secure guest
 *
 * We first mark the pages to be skipped from UV_PAGE_OUT when there
 * is HV side fault on these pages. Next we *get* these pages, forcing
 * fault on them, do fault time migration to replace the device PTEs in
 * QEMU page table with normal PTEs from newly allocated pages.
 */
void kvmppc_uvmem_drop_pages(const struct kvm_memory_slot *free,
			     struct kvm *kvm, bool skip_page_out)
{
	int i;
	struct kvmppc_uvmem_page_pvt *pvt;
	unsigned long pfn, uvmem_pfn;
	unsigned long gfn = free->base_gfn;

	for (i = free->npages; i; --i, ++gfn) {
		struct page *uvmem_page;

		mutex_lock(&kvm->arch.uvmem_lock);
		if (!kvmppc_gfn_is_uvmem_pfn(gfn, kvm, &uvmem_pfn)) {
			mutex_unlock(&kvm->arch.uvmem_lock);
			continue;
		}

		uvmem_page = pfn_to_page(uvmem_pfn);
		pvt = uvmem_page->zone_device_data;
		pvt->skip_page_out = skip_page_out;
		mutex_unlock(&kvm->arch.uvmem_lock);

		pfn = gfn_to_pfn(kvm, gfn);
		if (is_error_noslot_pfn(pfn))
			continue;
		kvm_release_pfn_clean(pfn);
	}
}

unsigned long kvmppc_h_svm_init_abort(struct kvm *kvm)
{
	int srcu_idx;
	struct kvm_memory_slot *memslot;

	/*
	 * Expect to be called only after INIT_START and before INIT_DONE.
	 * If INIT_DONE was completed, use normal VM termination sequence.
	 */
	if (!(kvm->arch.secure_guest & KVMPPC_SECURE_INIT_START))
		return H_UNSUPPORTED;

	if (kvm->arch.secure_guest & KVMPPC_SECURE_INIT_DONE)
		return H_STATE;

	srcu_idx = srcu_read_lock(&kvm->srcu);

	kvm_for_each_memslot(memslot, kvm_memslots(kvm))
		kvmppc_uvmem_drop_pages(memslot, kvm, false);

	srcu_read_unlock(&kvm->srcu, srcu_idx);

	kvm->arch.secure_guest = 0;
	uv_svm_terminate(kvm->arch.lpid);

	return H_PARAMETER;
}

/*
 * Get a free device PFN from the pool
 *
 * Called when a normal page is moved to secure memory (UV_PAGE_IN). Device
 * PFN will be used to keep track of the secure page on HV side.
 *
 * Called with kvm->arch.uvmem_lock held
 */
static struct page *kvmppc_uvmem_get_page(unsigned long gpa, struct kvm *kvm)
{
	struct page *dpage = NULL;
	unsigned long bit, uvmem_pfn;
	struct kvmppc_uvmem_page_pvt *pvt;
	unsigned long pfn_last, pfn_first;

	pfn_first = kvmppc_uvmem_pgmap.res.start >> PAGE_SHIFT;
	pfn_last = pfn_first +
		   (resource_size(&kvmppc_uvmem_pgmap.res) >> PAGE_SHIFT);

	spin_lock(&kvmppc_uvmem_bitmap_lock);
	bit = find_first_zero_bit(kvmppc_uvmem_bitmap,
				  pfn_last - pfn_first);
	if (bit >= (pfn_last - pfn_first))
		goto out;
	bitmap_set(kvmppc_uvmem_bitmap, bit, 1);
	spin_unlock(&kvmppc_uvmem_bitmap_lock);

	pvt = kzalloc(sizeof(*pvt), GFP_KERNEL);
	if (!pvt)
		goto out_clear;

	uvmem_pfn = bit + pfn_first;
	kvmppc_uvmem_pfn_insert(gpa >> PAGE_SHIFT, uvmem_pfn, kvm);

	pvt->gpa = gpa;
	pvt->kvm = kvm;

	dpage = pfn_to_page(uvmem_pfn);
	dpage->zone_device_data = pvt;
	get_page(dpage);
	lock_page(dpage);
	return dpage;
out_clear:
	spin_lock(&kvmppc_uvmem_bitmap_lock);
	bitmap_clear(kvmppc_uvmem_bitmap, bit, 1);
out:
	spin_unlock(&kvmppc_uvmem_bitmap_lock);
	return NULL;
}

/*
 * Alloc a PFN from private device memory pool and copy page from normal
 * memory to secure memory using UV_PAGE_IN uvcall.
 */
static int
kvmppc_svm_page_in(struct vm_area_struct *vma, unsigned long start,
		   unsigned long end, unsigned long gpa, struct kvm *kvm,
		   unsigned long page_shift, bool *downgrade)
{
	unsigned long src_pfn, dst_pfn = 0;
	struct migrate_vma mig;
	struct page *spage;
	unsigned long pfn;
	struct page *dpage;
	int ret = 0;

	memset(&mig, 0, sizeof(mig));
	mig.vma = vma;
	mig.start = start;
	mig.end = end;
	mig.src = &src_pfn;
	mig.dst = &dst_pfn;

	/*
	 * We come here with mmap_sem write lock held just for
	 * ksm_madvise(), otherwise we only need read mmap_sem.
	 * Hence downgrade to read lock once ksm_madvise() is done.
	 */
	ret = ksm_madvise(vma, vma->vm_start, vma->vm_end,
			  MADV_UNMERGEABLE, &vma->vm_flags);
	downgrade_write(&kvm->mm->mmap_sem);
	*downgrade = true;
	if (ret)
		return ret;

	ret = migrate_vma_setup(&mig);
	if (ret)
		return ret;

	if (!(*mig.src & MIGRATE_PFN_MIGRATE)) {
		ret = -1;
		goto out_finalize;
	}

	dpage = kvmppc_uvmem_get_page(gpa, kvm);
	if (!dpage) {
		ret = -1;
		goto out_finalize;
	}

	pfn = *mig.src >> MIGRATE_PFN_SHIFT;
	spage = migrate_pfn_to_page(*mig.src);
	if (spage)
		uv_page_in(kvm->arch.lpid, pfn << page_shift, gpa, 0,
			   page_shift);

	*mig.dst = migrate_pfn(page_to_pfn(dpage)) | MIGRATE_PFN_LOCKED;
	migrate_vma_pages(&mig);
out_finalize:
	migrate_vma_finalize(&mig);
	return ret;
}

/*
 * Shares the page with HV, thus making it a normal page.
 *
 * - If the page is already secure, then provision a new page and share
 * - If the page is a normal page, share the existing page
 *
 * In the former case, uses dev_pagemap_ops.migrate_to_ram handler
 * to unmap the device page from QEMU's page tables.
 */
static unsigned long
kvmppc_share_page(struct kvm *kvm, unsigned long gpa, unsigned long page_shift)
{

	int ret = H_PARAMETER;
	struct page *uvmem_page;
	struct kvmppc_uvmem_page_pvt *pvt;
	unsigned long pfn;
	unsigned long gfn = gpa >> page_shift;
	int srcu_idx;
	unsigned long uvmem_pfn;

	srcu_idx = srcu_read_lock(&kvm->srcu);
	mutex_lock(&kvm->arch.uvmem_lock);
	if (kvmppc_gfn_is_uvmem_pfn(gfn, kvm, &uvmem_pfn)) {
		uvmem_page = pfn_to_page(uvmem_pfn);
		pvt = uvmem_page->zone_device_data;
		pvt->skip_page_out = true;
	}

retry:
	mutex_unlock(&kvm->arch.uvmem_lock);
	pfn = gfn_to_pfn(kvm, gfn);
	if (is_error_noslot_pfn(pfn))
		goto out;

	mutex_lock(&kvm->arch.uvmem_lock);
	if (kvmppc_gfn_is_uvmem_pfn(gfn, kvm, &uvmem_pfn)) {
		uvmem_page = pfn_to_page(uvmem_pfn);
		pvt = uvmem_page->zone_device_data;
		pvt->skip_page_out = true;
		kvm_release_pfn_clean(pfn);
		goto retry;
	}

	if (!uv_page_in(kvm->arch.lpid, pfn << page_shift, gpa, 0, page_shift))
		ret = H_SUCCESS;
	kvm_release_pfn_clean(pfn);
	mutex_unlock(&kvm->arch.uvmem_lock);
out:
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return ret;
}

/*
 * H_SVM_PAGE_IN: Move page from normal memory to secure memory.
 *
 * H_PAGE_IN_SHARED flag makes the page shared which means that the same
 * memory in is visible from both UV and HV.
 */
unsigned long
kvmppc_h_svm_page_in(struct kvm *kvm, unsigned long gpa,
		     unsigned long flags, unsigned long page_shift)
{
	bool downgrade = false;
	unsigned long start, end;
	struct vm_area_struct *vma;
	int srcu_idx;
	unsigned long gfn = gpa >> page_shift;
	int ret;

	if (!(kvm->arch.secure_guest & KVMPPC_SECURE_INIT_START))
		return H_UNSUPPORTED;

	if (page_shift != PAGE_SHIFT)
		return H_P3;

	if (flags & ~H_PAGE_IN_SHARED)
		return H_P2;

	if (flags & H_PAGE_IN_SHARED)
		return kvmppc_share_page(kvm, gpa, page_shift);

	ret = H_PARAMETER;
	srcu_idx = srcu_read_lock(&kvm->srcu);
	down_write(&kvm->mm->mmap_sem);

	start = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(start))
		goto out;

	mutex_lock(&kvm->arch.uvmem_lock);
	/* Fail the page-in request of an already paged-in page */
	if (kvmppc_gfn_is_uvmem_pfn(gfn, kvm, NULL))
		goto out_unlock;

	end = start + (1UL << page_shift);
	vma = find_vma_intersection(kvm->mm, start, end);
	if (!vma || vma->vm_start > start || vma->vm_end < end)
		goto out_unlock;

	if (!kvmppc_svm_page_in(vma, start, end, gpa, kvm, page_shift,
				&downgrade))
		ret = H_SUCCESS;
out_unlock:
	mutex_unlock(&kvm->arch.uvmem_lock);
out:
	if (downgrade)
		up_read(&kvm->mm->mmap_sem);
	else
		up_write(&kvm->mm->mmap_sem);
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return ret;
}

/*
 * Provision a new page on HV side and copy over the contents
 * from secure memory using UV_PAGE_OUT uvcall.
 */
static int
kvmppc_svm_page_out(struct vm_area_struct *vma, unsigned long start,
		    unsigned long end, unsigned long page_shift,
		    struct kvm *kvm, unsigned long gpa)
{
	unsigned long src_pfn, dst_pfn = 0;
	struct migrate_vma mig;
	struct page *dpage, *spage;
	struct kvmppc_uvmem_page_pvt *pvt;
	unsigned long pfn;
	int ret = U_SUCCESS;

	memset(&mig, 0, sizeof(mig));
	mig.vma = vma;
	mig.start = start;
	mig.end = end;
	mig.src = &src_pfn;
	mig.dst = &dst_pfn;
	mig.src_owner = &kvmppc_uvmem_pgmap;

	mutex_lock(&kvm->arch.uvmem_lock);
	/* The requested page is already paged-out, nothing to do */
	if (!kvmppc_gfn_is_uvmem_pfn(gpa >> page_shift, kvm, NULL))
		goto out;

	ret = migrate_vma_setup(&mig);
	if (ret)
		goto out;

	spage = migrate_pfn_to_page(*mig.src);
	if (!spage || !(*mig.src & MIGRATE_PFN_MIGRATE))
		goto out_finalize;

	if (!is_zone_device_page(spage))
		goto out_finalize;

	dpage = alloc_page_vma(GFP_HIGHUSER, vma, start);
	if (!dpage) {
		ret = -1;
		goto out_finalize;
	}

	lock_page(dpage);
	pvt = spage->zone_device_data;
	pfn = page_to_pfn(dpage);

	/*
	 * This function is used in two cases:
	 * - When HV touches a secure page, for which we do UV_PAGE_OUT
	 * - When a secure page is converted to shared page, we *get*
	 *   the page to essentially unmap the device page. In this
	 *   case we skip page-out.
	 */
	if (!pvt->skip_page_out)
		ret = uv_page_out(kvm->arch.lpid, pfn << page_shift,
				  gpa, 0, page_shift);

	if (ret == U_SUCCESS)
		*mig.dst = migrate_pfn(pfn) | MIGRATE_PFN_LOCKED;
	else {
		unlock_page(dpage);
		__free_page(dpage);
		goto out_finalize;
	}

	migrate_vma_pages(&mig);
out_finalize:
	migrate_vma_finalize(&mig);
out:
	mutex_unlock(&kvm->arch.uvmem_lock);
	return ret;
}

/*
 * Fault handler callback that gets called when HV touches any page that
 * has been moved to secure memory, we ask UV to give back the page by
 * issuing UV_PAGE_OUT uvcall.
 *
 * This eventually results in dropping of device PFN and the newly
 * provisioned page/PFN gets populated in QEMU page tables.
 */
static vm_fault_t kvmppc_uvmem_migrate_to_ram(struct vm_fault *vmf)
{
	struct kvmppc_uvmem_page_pvt *pvt = vmf->page->zone_device_data;

	if (kvmppc_svm_page_out(vmf->vma, vmf->address,
				vmf->address + PAGE_SIZE, PAGE_SHIFT,
				pvt->kvm, pvt->gpa))
		return VM_FAULT_SIGBUS;
	else
		return 0;
}

/*
 * Release the device PFN back to the pool
 *
 * Gets called when secure page becomes a normal page during H_SVM_PAGE_OUT.
 * Gets called with kvm->arch.uvmem_lock held.
 */
static void kvmppc_uvmem_page_free(struct page *page)
{
	unsigned long pfn = page_to_pfn(page) -
			(kvmppc_uvmem_pgmap.res.start >> PAGE_SHIFT);
	struct kvmppc_uvmem_page_pvt *pvt;

	spin_lock(&kvmppc_uvmem_bitmap_lock);
	bitmap_clear(kvmppc_uvmem_bitmap, pfn, 1);
	spin_unlock(&kvmppc_uvmem_bitmap_lock);

	pvt = page->zone_device_data;
	page->zone_device_data = NULL;
	kvmppc_uvmem_pfn_remove(pvt->gpa >> PAGE_SHIFT, pvt->kvm);
	kfree(pvt);
}

static const struct dev_pagemap_ops kvmppc_uvmem_ops = {
	.page_free = kvmppc_uvmem_page_free,
	.migrate_to_ram	= kvmppc_uvmem_migrate_to_ram,
};

/*
 * H_SVM_PAGE_OUT: Move page from secure memory to normal memory.
 */
unsigned long
kvmppc_h_svm_page_out(struct kvm *kvm, unsigned long gpa,
		      unsigned long flags, unsigned long page_shift)
{
	unsigned long gfn = gpa >> page_shift;
	unsigned long start, end;
	struct vm_area_struct *vma;
	int srcu_idx;
	int ret;

	if (!(kvm->arch.secure_guest & KVMPPC_SECURE_INIT_START))
		return H_UNSUPPORTED;

	if (page_shift != PAGE_SHIFT)
		return H_P3;

	if (flags)
		return H_P2;

	ret = H_PARAMETER;
	srcu_idx = srcu_read_lock(&kvm->srcu);
	down_read(&kvm->mm->mmap_sem);
	start = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(start))
		goto out;

	end = start + (1UL << page_shift);
	vma = find_vma_intersection(kvm->mm, start, end);
	if (!vma || vma->vm_start > start || vma->vm_end < end)
		goto out;

	if (!kvmppc_svm_page_out(vma, start, end, page_shift, kvm, gpa))
		ret = H_SUCCESS;
out:
	up_read(&kvm->mm->mmap_sem);
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return ret;
}

int kvmppc_send_page_to_uv(struct kvm *kvm, unsigned long gfn)
{
	unsigned long pfn;
	int ret = U_SUCCESS;

	pfn = gfn_to_pfn(kvm, gfn);
	if (is_error_noslot_pfn(pfn))
		return -EFAULT;

	mutex_lock(&kvm->arch.uvmem_lock);
	if (kvmppc_gfn_is_uvmem_pfn(gfn, kvm, NULL))
		goto out;

	ret = uv_page_in(kvm->arch.lpid, pfn << PAGE_SHIFT, gfn << PAGE_SHIFT,
			 0, PAGE_SHIFT);
out:
	kvm_release_pfn_clean(pfn);
	mutex_unlock(&kvm->arch.uvmem_lock);
	return (ret == U_SUCCESS) ? RESUME_GUEST : -EFAULT;
}

static u64 kvmppc_get_secmem_size(void)
{
	struct device_node *np;
	int i, len;
	const __be32 *prop;
	u64 size = 0;

	np = of_find_compatible_node(NULL, NULL, "ibm,uv-firmware");
	if (!np)
		goto out;

	prop = of_get_property(np, "secure-memory-ranges", &len);
	if (!prop)
		goto out_put;

	for (i = 0; i < len / (sizeof(*prop) * 4); i++)
		size += of_read_number(prop + (i * 4) + 2, 2);

out_put:
	of_node_put(np);
out:
	return size;
}

int kvmppc_uvmem_init(void)
{
	int ret = 0;
	unsigned long size;
	struct resource *res;
	void *addr;
	unsigned long pfn_last, pfn_first;

	size = kvmppc_get_secmem_size();
	if (!size) {
		/*
		 * Don't fail the initialization of kvm-hv module if
		 * the platform doesn't export ibm,uv-firmware node.
		 * Let normal guests run on such PEF-disabled platform.
		 */
		pr_info("KVMPPC-UVMEM: No support for secure guests\n");
		goto out;
	}

	res = request_free_mem_region(&iomem_resource, size, "kvmppc_uvmem");
	if (IS_ERR(res)) {
		ret = PTR_ERR(res);
		goto out;
	}

	kvmppc_uvmem_pgmap.type = MEMORY_DEVICE_PRIVATE;
	kvmppc_uvmem_pgmap.res = *res;
	kvmppc_uvmem_pgmap.ops = &kvmppc_uvmem_ops;
	/* just one global instance: */
	kvmppc_uvmem_pgmap.owner = &kvmppc_uvmem_pgmap;
	addr = memremap_pages(&kvmppc_uvmem_pgmap, NUMA_NO_NODE);
	if (IS_ERR(addr)) {
		ret = PTR_ERR(addr);
		goto out_free_region;
	}

	pfn_first = res->start >> PAGE_SHIFT;
	pfn_last = pfn_first + (resource_size(res) >> PAGE_SHIFT);
	kvmppc_uvmem_bitmap = kcalloc(BITS_TO_LONGS(pfn_last - pfn_first),
				      sizeof(unsigned long), GFP_KERNEL);
	if (!kvmppc_uvmem_bitmap) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	pr_info("KVMPPC-UVMEM: Secure Memory size 0x%lx\n", size);
	return ret;
out_unmap:
	memunmap_pages(&kvmppc_uvmem_pgmap);
out_free_region:
	release_mem_region(res->start, size);
out:
	return ret;
}

void kvmppc_uvmem_free(void)
{
	if (!kvmppc_uvmem_bitmap)
		return;

	memunmap_pages(&kvmppc_uvmem_pgmap);
	release_mem_region(kvmppc_uvmem_pgmap.res.start,
			   resource_size(&kvmppc_uvmem_pgmap.res));
	kfree(kvmppc_uvmem_bitmap);
}

static struct ucall_worker *kvmppc_ucall_worker_init(struct kvm_vcpu *vcpu, kvm_vm_thread_fn_t fn)
{
	struct ucall_worker *worker;
	int r = 0;

	worker = kzalloc(sizeof(struct ucall_worker), GFP_KERNEL);
	if (!worker)
		return NULL;

	init_completion(&worker->step_done);
	init_completion(&worker->hcall_done);
	worker->thread_fn = fn;
	worker->vcpu = vcpu;

	r = kvm_vm_create_worker_thread(vcpu->kvm, worker->thread_fn, (uintptr_t)worker, "kvm_ucall_worker",
					&worker->thread);
	if (r) {
		kfree(worker);
		return NULL;
	}

	return worker;
}

static void kvmppc_ucall_worker_wait(struct ucall_worker *worker)
{
	worker->ret = U_TOO_HARD;
	complete(&worker->step_done);
	wait_for_completion(&worker->hcall_done);

	reinit_completion(&worker->hcall_done);
}

static void __noreturn kvmppc_ucall_worker_exit(struct ucall_worker *worker, unsigned long ret)
{
	worker->ret = ret;
	worker->in_progress = false;
	complete_and_exit(&worker->step_done, 0);
}

static void __kvmppc_ucall_worker_step(struct kvm_vcpu *vcpu, struct ucall_worker *worker)
{
	if (!worker->in_progress) {
		worker->in_progress = true;
		kthread_unpark(worker->thread);
	} else {
		reinit_completion(&worker->step_done);
		complete(&worker->hcall_done);
	}

	wait_for_completion(&worker->step_done);
}

/*
 * This function is called to make progress with an ultracall in L0
 * that needs assistance from the nested hypervisor. The ucall handler
 * runs in a separate thread and does so in steps separated by
 * hypercall requests. Returns U_TOO_HARD while there is still work to
 * be done.
 */
unsigned long kvmppc_ucall_do_work(struct kvm_vcpu *vcpu, struct ucall_worker **w, kvm_vm_thread_fn_t work_fn)
{
	struct ucall_worker *worker = *w;
        unsigned long ret;

        if (!worker) {
                worker = kvmppc_ucall_worker_init(vcpu, work_fn);
                if (!worker)
                        return U_NO_MEM;
                *w = worker;
        }

        __kvmppc_ucall_worker_step(vcpu, worker);
	ret = worker->ret;

        if (!worker->in_progress) {
                kfree(worker);
                *w = NULL;
        }

        return ret;
}

static unsigned long do_l1_hcall(struct kvm_vcpu *vcpu, struct ucall_worker *worker, unsigned long hcall)
{
	/* set the registers as if L2 was doing the hcall */
	kvmppc_set_gpr(vcpu, 3, hcall);
	kvmppc_set_srr1(vcpu, kvmppc_get_srr1(vcpu) | MSR_S);
	vcpu->arch.trap = BOOK3S_INTERRUPT_SYSCALL;

	/* wait for L1 */
	kvmppc_ucall_worker_wait(worker);

	return kvmppc_get_gpr(vcpu, 3);
}

/*
 * Handle the UV_ESM ucall.
 * r4 = secure guest's kernel base address
 * r5 = secure guest's firmware device tree address
 */
int kvmppc_uv_esm_work_fn(struct kvm *kvm, uintptr_t thread_data)
{
	struct ucall_worker *uv_esm = (struct ucall_worker *)thread_data;
	struct kvm_vcpu *vcpu = uv_esm->vcpu;
	unsigned long kbase = kvmppc_get_gpr(vcpu, 4);
	unsigned long fdt = kvmppc_get_gpr(vcpu, 5);
	unsigned long r;
	// not documented
	unsigned long ret = U_FUNCTION;

	if (!kbase) {
		// not documented
		ret = U_PARAMETER;
		goto out;
	}

	if (!fdt) {
		ret = U_P2;
		goto out;
	}

	if (kvmppc_get_srr1(vcpu) & (MSR_HV|MSR_PR)) {
		ret = U_PERMISSION;
		goto out;
	}

	r = do_l1_hcall(vcpu, uv_esm, H_SVM_INIT_START);
	if (r != U_SUCCESS)
		goto out;

	r = do_l1_hcall(vcpu, uv_esm, H_SVM_INIT_DONE);

out:
	kvmppc_ucall_worker_exit(uv_esm, ret);
}

struct kvm_nested_memslots *kvmppc_alloc_nested_slots(size_t size)
{
	struct kvm_nested_memslots *slots;
	int i;

	slots = kvzalloc(size, GFP_KERNEL_ACCOUNT);
	if (!slots)
		return NULL;

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++)
		slots->id_to_index[i] = -1;

	return slots;
}

void kvmppc_free_nested_slots(struct kvm_nested_memslots *slots)
{
	if (!slots)
		return;
	kvfree(slots);
}

static struct kvm_nested_memslots *realloc_nested_slots(struct kvm_nested_memslots *old_slots, int nslots)
{
	struct kvm_nested_memslots *slots;
	size_t size;

	if (!old_slots)
		return NULL;

	size = sizeof(struct kvm_nested_memslots) +
		(sizeof(struct kvm_memory_slot) * nslots);

	slots = kvmppc_alloc_nested_slots(size);
	if (!slots)
		return NULL;

	memcpy(slots, old_slots, size);
	kvmppc_free_nested_slots(old_slots);

	return slots;
}

static const struct kvm_memory_slot *get_memslot(struct kvm_nested_memslots *slots, short slot_id)
{
	short i;

	if (!slots || slot_id >= KVM_MEM_SLOTS_NUM || slot_id < 0)
		return NULL;

	i = slots->id_to_index[slot_id];
	if (i < 0)
		return NULL;

	return &slots->memslots[i];
}
/*
static bool kvmppc_gfn_range_valid(struct kvm_nested_memslots *slots, gfn_t base_gfn, unsigned long npages)
{
	struct kvm_memory_slot *tmp;
	gfn_t end_gfn;

	if (npages <= 0)
		return false;

	end_gfn = base_gfn + npages;

	kvm_for_each_memslot(tmp, slots) {
		if (end_gfn > tmp->base_gfn + tmp->npages)
			return false;

		if (base_gfn >= tmp->base_gfn)
			return true;

		if (end_gfn >= tmp->base_gfn)
			end_gfn = tmp->base_gfn - 1;
	}

	return false;
}
*/
/* Move this memslot to the end of the list and erase it. The caller
 * might use the extra space to hold another memslot. */
static void delete_memslot(struct kvm_nested_memslots *slots, const struct kvm_memory_slot *memslot)
{
	short id = memslot->id;
	int i;

	for (i = slots->id_to_index[id]; i < slots->used_slots - 1; i++) {
		slots->memslots[i] = slots->memslots[i + 1];
		slots->id_to_index[slots->memslots[i].id] = i;
	}

	slots->memslots[i] = *memslot;
	memset(&slots->memslots[i], 0, sizeof(*memslot));
	slots->id_to_index[id] = -1;
	slots->used_slots--;
}

/* Move all memslots after 'pos' one position forward and insert the
 * memslot. */
static void insert_memslot(struct kvm_nested_memslots *slots, struct kvm_memory_slot *memslot, int pos)
{
	int i;

	for (i = slots->used_slots; i > pos; i--) {
		slots->memslots[i] = slots->memslots[i - 1];
		slots->id_to_index[slots->memslots[i].id] = i;
	}

	slots->memslots[pos] = *memslot;
	slots->id_to_index[memslot->id] = pos;
	slots->used_slots++;
}

static struct kvm_nested_memslots *update_memslots(struct kvm_nested_memslots *old_slots,
						   const struct kvm_memory_slot *old,
						   struct kvm_memory_slot *new, int pos)
{
	struct kvm_nested_memslots *new_slots;
	int nslots;

	if (!old_slots || (!old && !new))
		return NULL;

	if (old)
		delete_memslot(old_slots, old);

	nslots = old_slots->used_slots;
	if (new)
		nslots += 1;

	new_slots = realloc_nested_slots(old_slots, nslots);
	if (new_slots && new)
		insert_memslot(new_slots, new, pos);

	return new_slots;
}

static int kvmppc_insert_nested_memslot(struct kvm_nested_guest *nested_guest, struct kvm_memory_slot *new)
{
	struct kvm_nested_memslots *new_slots, *slots = nested_guest->memslots;
	struct kvm_memory_slot *tmp;
	const struct kvm_memory_slot *old;
	int i, pos;

	if (!new)
		return -EINVAL;

	old = get_memslot(slots, new->id);

	if (slots->used_slots >= KVM_MEM_SLOTS_NUM && !old)
		/* can't fit anymore slots */
		return -EINVAL;

	for (i = 0, pos = 0; i < slots->used_slots; i++, pos++) {
		tmp = &slots->memslots[i];

		/* new goes before tmp */
		if (new->base_gfn >= tmp->base_gfn + tmp->npages) {
			break;
		}

		/* new goes after tmp */
		if (new->base_gfn + new->npages <= tmp->base_gfn) {
			/* walked past the slot we're trying to move */
			if (old && new->id == tmp->id)
				pos--;
			continue;
		}

		/* overlap */
		return -EEXIST;
	}

	new_slots = update_memslots(slots, old, new, pos);
	if (!new_slots)
		return -ENOMEM;
	nested_guest->memslots = new_slots;
	return 0;
}

static int kvmppc_remove_nested_memslot(struct kvm_nested_guest *nested_guest, const struct kvm_memory_slot *old)
{
	struct kvm_nested_memslots *new_slots, *slots = nested_guest->memslots;

	if (!old)
		return -EINVAL;

	new_slots = update_memslots(slots, old, NULL, 0);
	if (!new_slots)
		return -ENOMEM;
	nested_guest->memslots = new_slots;

	return 0;
}

static void print_slots(struct kvm_nested_memslots *s)
{
	struct kvm_memory_slot *m;

	printk(KERN_DEBUG "memslots:");
	printk(KERN_DEBUG " -> (%px=%d)\n", s, s->used_slots);
/*
{
	int i;
	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
		printk(KERN_CONT " -> id %d=%d", i, s->id_to_index[i]);
	}
	printk(KERN_CONT " | ");
}
*/

	kvm_for_each_memslot(m, s) {
		printk(KERN_CONT " -> (%d=%d,%llx,%ld)", s->id_to_index[m->id], m->id, m->base_gfn, m->npages);
	}
	printk(KERN_DEBUG "# memslots\n");
}

int __test_insert_memslot(struct kvm_nested_guest *gp, short slot_id)
{
	struct kvm_memory_slot new;
	unsigned long nbytes;
	gpa_t gpa;
	int r;

	get_random_bytes(&gpa, sizeof(gpa));
	get_random_bytes(&nbytes, sizeof(nbytes));

	new.base_gfn = gpa;
	new.npages = (nbytes % 100) + 1;
	new.id = slot_id;

	spin_lock(&gp->slots_lock);
	r = kvmppc_insert_nested_memslot(gp, &new);
	spin_unlock(&gp->slots_lock);

	return r;
}

int __test_remove_memslot(struct kvm_nested_guest *gp, short slot_id)
{
	const struct kvm_memory_slot *old;
	int r;

	old = get_memslot(gp->memslots, slot_id);
	if (!old)
		return -1;

	spin_lock(&gp->slots_lock);
	r = kvmppc_remove_nested_memslot(gp, old);
	spin_unlock(&gp->slots_lock);

	return r;
}

bool test_memslot_remove_all(struct kvm_nested_guest *gp)
{
	int r, i;
	int nslots = gp->memslots->used_slots;

	printk(KERN_DEBUG "remove all\n");
	for (i=0; i < nslots; i++) {
		r = __test_remove_memslot(gp, i);
		if (r < 0)
			return false;
	}
	return true;
}

bool test_memslot_insert_range_random(struct kvm_nested_guest *gp, int start, int end)
{
	int i, r;

	printk(KERN_DEBUG "insert range %d-%d\n", start, end);
	for (i=start; i < end; i++) {
		r = __test_insert_memslot(gp, i);
		if (r < 0)
			return false;
	}
	return true;
}

bool test_memslot_insert_half(struct kvm_nested_guest *gp)
{
	return test_memslot_insert_range_random(gp, 0, KVM_MEM_SLOTS_NUM/2);
}

bool test_memslot_insert_all(struct kvm_nested_guest *gp)
{
	return test_memslot_insert_range_random(gp, 0, KVM_MEM_SLOTS_NUM);
}

bool test_memslot_insert_all_out_of_bounds(struct kvm_nested_guest *gp)
{
	return !test_memslot_insert_range_random(gp, 0, KVM_MEM_SLOTS_NUM + 2);
}

bool test_memslot_move(struct kvm_nested_guest *gp)
{
	int i, r;
	short slot_id;

	printk(KERN_DEBUG "insert all sorted\n");
	for (i=0; i < KVM_MEM_SLOTS_NUM; i++) {
		struct kvm_memory_slot new;

		new.base_gfn = i * 100;
		new.npages = 2;
		new.id = i;

		spin_lock(&gp->slots_lock);
		r = kvmppc_insert_nested_memslot(gp, &new);
		spin_unlock(&gp->slots_lock);

		if (r < 0)
			return false;
	}
	slot_id = gp->memslots->used_slots - 7;
	printk(KERN_DEBUG "move id=%d\n", slot_id);
	{
		struct kvm_memory_slot new;
		gpa_t gpa = 512 * 100;
		unsigned long nbytes = 100;

		new.base_gfn = gpa;
		new.npages = nbytes;
		new.id = slot_id;

		spin_lock(&gp->slots_lock);
		r = kvmppc_insert_nested_memslot(gp, &new);
		spin_unlock(&gp->slots_lock);
		if (r < 0)
			return false;
	}

	return true;
}

bool test_memslot_clash(struct kvm_nested_guest *gp)
{
	int r;

	printk(KERN_DEBUG "clash id=1\n");
	{
		struct kvm_memory_slot new;
		gpa_t gpa = 3 * 100;
		unsigned long nbytes = 100;

		new.base_gfn = gpa;
		new.npages = nbytes;
		new.id = 1;

		spin_lock(&gp->slots_lock);
		r = kvmppc_insert_nested_memslot(gp, &new);
		spin_unlock(&gp->slots_lock);

		if (r < 0)
			return true;
	}
	return false;
}

static void test_memslot_registration(struct kvm_nested_guest *gp)
{
	int i;
	bool r;
	bool (*tests [])(struct kvm_nested_guest *gp) = {
		test_memslot_insert_all,
		test_memslot_remove_all,
		test_memslot_insert_all_out_of_bounds,
		test_memslot_remove_all,
		test_memslot_insert_half,
		test_memslot_remove_all,
		test_memslot_move,
		test_memslot_clash,
		test_memslot_remove_all,
	};

	printk(KERN_DEBUG "pre-test\n");
	for (i=0; i < ARRAY_SIZE(tests); i++) {
		r = tests[i](gp);
		print_slots(gp->memslots);
		if (!r) {
			WARN_ON(1);
			break;
		}
	}
	printk(KERN_DEBUG "end test\n");
}

static void print_slots(struct kvm_nested_guest *gp)
{
	struct kvm_memory_slot *m;
	struct kvm_nested_memslots *s = gp->memslots;

	printk(KERN_DEBUG "memslots:");
	printk(KERN_DEBUG " -> (%px=%d)\n", s, s->used_slots);
/*
{
	int i;
	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
		printk(KERN_CONT " -> id %d=%d", i, s->id_to_index[i]);
	}
	printk(KERN_CONT " | ");
}
*/

	spin_lock(&gp->slots_lock);
	kvm_for_each_memslot(m, s) {
		printk(KERN_CONT " -> (%d=%d,%llx,%ld)", s->id_to_index[m->id], m->id, m->base_gfn, m->npages);
	}
	spin_unlock(&gp->slots_lock);
	printk(KERN_DEBUG "# memslots\n");
}

int __test_insert_memslot(struct kvm_nested_guest *gp, short slot_id)
{
	struct kvm_memory_slot new;
	unsigned long nbytes;
	gpa_t gpa;
	int r;

	get_random_bytes(&gpa, sizeof(gpa));
	get_random_bytes(&nbytes, sizeof(nbytes));

	new.base_gfn = gpa;
	new.npages = (nbytes % 100) + 1;
	new.id = slot_id;

	r = kvmppc_insert_nested_memslot(gp, &new);
	return r;
}

int __test_remove_memslot(struct kvm_nested_guest *gp, short slot_id)
{
	int r;

	r = kvmppc_remove_nested_memslot(gp, slot_id);
	return r;
}

bool test_memslot_remove_all(struct kvm_nested_guest *gp)
{
	int r, i;
	int nslots = gp->memslots->used_slots;

	printk(KERN_DEBUG "remove all\n");
	for (i=0; i < nslots; i++) {
		r = __test_remove_memslot(gp, i);
		if (r < 0)
			return false;
	}
	return true;
}

bool test_memslot_insert_range_random(struct kvm_nested_guest *gp, int start, int end)
{
	int i, r;

	printk(KERN_DEBUG "insert range %d-%d\n", start, end);
	for (i=start; i < end; i++) {
		r = __test_insert_memslot(gp, i);
		if (r < 0)
			return false;
	}
	return true;
}

bool test_memslot_insert_half(struct kvm_nested_guest *gp)
{
	return test_memslot_insert_range_random(gp, 0, KVM_MEM_SLOTS_NUM/2);
}

bool test_memslot_insert_all(struct kvm_nested_guest *gp)
{
	return test_memslot_insert_range_random(gp, 0, KVM_MEM_SLOTS_NUM);
}

bool test_memslot_insert_all_out_of_bounds(struct kvm_nested_guest *gp)
{
	return !test_memslot_insert_range_random(gp, 0, KVM_MEM_SLOTS_NUM + 2);
}

bool test_memslot_order(struct kvm_nested_guest *gp)
{
	struct kvm_memory_slot *tmp, *next;
	struct kvm_nested_memslots *slots;
	int i;

	printk(KERN_DEBUG "check order\n");
	spin_lock(&gp->slots_lock);
	slots = gp->memslots;
	for (i = 0; i < slots->used_slots - 1; i++) {
		tmp = &slots->memslots[i];
		next = &slots->memslots[i + 1];

		if (tmp->base_gfn <= next->base_gfn) {
			spin_unlock(&gp->slots_lock);
			return false;
		}
	}
	spin_unlock(&gp->slots_lock);
	return true;
}

bool test_memslot_move(struct kvm_nested_guest *gp)
{
	int i, r;
	short slot_id;

	printk(KERN_DEBUG "insert all sorted\n");
	for (i=0; i < KVM_MEM_SLOTS_NUM; i++) {
		struct kvm_memory_slot new;

		new.base_gfn = i * 100;
		new.npages = 2;
		new.id = i;

		r = kvmppc_insert_nested_memslot(gp, &new);
		if (r < 0)
			return false;
	}
	slot_id = gp->memslots->used_slots - 7;
	printk(KERN_DEBUG "move id=%d\n", slot_id);
	{
		struct kvm_memory_slot new;
		gpa_t gpa = 512 * 100;
		unsigned long nbytes = 100;

		new.base_gfn = gpa;
		new.npages = nbytes;
		new.id = slot_id;

		r = kvmppc_insert_nested_memslot(gp, &new);
		if (r < 0)
			return false;
	}

	return true;
}

bool test_memslot_clash(struct kvm_nested_guest *gp)
{
	int r;

	printk(KERN_DEBUG "clash id=1\n");
	{
		struct kvm_memory_slot new;
		gpa_t gpa = 3 * 100;
		unsigned long nbytes = 100;

		new.base_gfn = gpa;
		new.npages = nbytes;
		new.id = 1;

		r = kvmppc_insert_nested_memslot(gp, &new);
		if (r < 0)
			return true;
	}
	return false;
}

static void test_memslot_registration(struct kvm_nested_guest *gp)
{
	int i;
	bool r;
	bool (*tests [])(struct kvm_nested_guest *gp) = {
		test_memslot_insert_all,
		test_memslot_order,
		test_memslot_remove_all,
		test_memslot_insert_all_out_of_bounds,
		test_memslot_order,
		test_memslot_remove_all,
		test_memslot_insert_half,
		test_memslot_order,
		test_memslot_remove_all,
		test_memslot_move,
		test_memslot_order,
		test_memslot_clash,
		test_memslot_order,
		test_memslot_remove_all,
	};

	printk(KERN_DEBUG "pre-test\n");
	for (i=0; i < ARRAY_SIZE(tests); i++) {
		r = tests[i](gp);
		print_slots(gp);
		if (!r) {
			WARN_ON(1);
			break;
		}
	}
	printk(KERN_DEBUG "end test\n");
}

/*
 * Handle the UV_REGISTER_MEM_SLOT ucall.
 * r4 = L1 lpid of secure guest
 * r5 = memslot start gpa
 * r6 = memslot size
 * r7 = flags
 * r8 = memslot id
 */
unsigned long kvmppc_uv_register_memslot(struct kvm_vcpu *vcpu, unsigned int lpid,
					 gpa_t gpa, unsigned long nbytes, unsigned long flags, short slot_id)
{
	struct kvm_nested_guest *nested_guest;
//	struct kvm_memory_slot new;
	unsigned long ret = U_SUCCESS;
	int r = 0;

	vcpu_debug(vcpu, "%s lpid=%d gpa=%llx nbytes=%lx flags=%lx slot_id=%d", __func__,
		   lpid, gpa, nbytes, flags, slot_id);

	if (gpa & (PAGE_SIZE - 1))
		return U_P2;

	if (!nbytes || gpa + nbytes < gpa)
		return U_P3;

	if (slot_id >= KVM_MEM_SLOTS_NUM)
		return U_P5;

	nested_guest = kvmhv_get_nested(vcpu->kvm, lpid, false);
	if (!nested_guest)
		return U_P4;

	test_memslot_registration(nested_guest);
/*
	new.base_gfn = gpa >> PAGE_SHIFT;
	new.npages = nbytes >> PAGE_SHIFT;
	new.id = slot_id;

	spin_lock(&nested_guest->slots_lock);
	r = kvmppc_insert_nested_memslot(nested_guest, &new);
*/
	if (r < 0)
		ret = U_P2;

	kvmhv_put_nested(nested_guest);
	return ret;
}

/*
 * Handle the UV_UNREGISTER_MEM_SLOT ucall.
 * r4 = L1 lpid of secure guest
 * r5 = memslot id
 */
unsigned long kvmppc_uv_unregister_memslot(struct kvm_vcpu *vcpu, unsigned int lpid, short slot_id)
{
	struct kvm_nested_guest *nested_guest;
	const struct kvm_memory_slot *old;
	unsigned long ret = U_SUCCESS;
	int r;

	vcpu_debug(vcpu, "%s lpid=%d slot_id=%d", __func__, lpid, slot_id);

	if (slot_id >= KVM_MEM_SLOTS_NUM)
		return U_P2;

	nested_guest = kvmhv_get_nested(vcpu->kvm, lpid, false);
	if (!nested_guest)
		return U_PARAMETER;

	old = get_memslot(nested_guest->memslots, slot_id);
	if (!old) {
		ret = U_P2;
		goto out;
	}

	spin_lock(&nested_guest->slots_lock);
	r = kvmppc_remove_nested_memslot(nested_guest, old);
	spin_unlock(&nested_guest->slots_lock);

	if (r < 0)
		ret = U_P2;

out:
	kvmhv_put_nested(nested_guest);
	return ret;
}
