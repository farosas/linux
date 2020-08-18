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
 * 2. kvm->mm->mmap_lock - find_vma, migrate_vma_pages and helpers, ksm_madvise
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
#include <linux/bsearch.h>
#include <asm/ultravisor.h>
#include <asm/mman.h>
#include <asm/kvm_ppc.h>
#include <asm/pte-walk.h>

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
	 * We come here with mmap_lock write lock held just for
	 * ksm_madvise(), otherwise we only need read mmap_lock.
	 * Hence downgrade to read lock once ksm_madvise() is done.
	 */
	ret = ksm_madvise(vma, vma->vm_start, vma->vm_end,
			  MADV_UNMERGEABLE, &vma->vm_flags);
	mmap_write_downgrade(kvm->mm);
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
	mmap_write_lock(kvm->mm);

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
		mmap_read_unlock(kvm->mm);
	else
		mmap_write_unlock(kvm->mm);
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
	mmap_read_lock(kvm->mm);
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
	mmap_read_unlock(kvm->mm);
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

	/*
	 * First try the new ibm,secure-memory nodes which supersede the
	 * secure-memory-ranges property.
	 * If we found some, no need to read the deprecated ones.
	 */
	for_each_compatible_node(np, NULL, "ibm,secure-memory") {
		prop = of_get_property(np, "reg", &len);
		if (!prop)
			continue;
		size += of_read_number(prop + 2, 2);
	}
	if (size)
		return size;

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

static bool uv_gfn_rmap_valid(unsigned long rmap)
{
	return ((rmap & KVMPPC_RMAP_TYPE_MASK) == KVMPPC_RMAP_UV_GFN);
}

static enum uv_gpf_state uv_gfn_state(unsigned long rmap)
{
	if (uv_gfn_rmap_valid(rmap))
		return rmap & KVMPPC_RMAP_UV_GPF_STATE_MASK;
	return GPF_SECURE;
}

static void uv_gfn_set_state(unsigned long *rmap, enum uv_gpf_state state)
{
	*rmap |= KVMPPC_RMAP_UV_GFN | (state & KVMPPC_RMAP_UV_GPF_STATE_MASK);
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

/* the next patch will make use of this
static void kvmppc_ucall_worker_wait(struct ucall_worker *worker)
{
	worker->ret = U_TOO_HARD;
	complete(&worker->step_done);
	wait_for_completion_killable(&worker->hcall_done);

	reinit_completion(&worker->hcall_done);
}
*/

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

int kvmppc_uv_esm_work_fn(struct kvm *kvm, uintptr_t thread_data)
{
	struct ucall_worker *uv_esm = (struct ucall_worker *)thread_data;

	kvmppc_ucall_worker_exit(uv_esm, U_UNSUPPORTED);
}

struct kvm_nested_memslots *kvmppc_alloc_nested_slots(void)
{
	struct kvm_nested_memslots *slots;
	int i;

	slots = kvzalloc(sizeof(struct kvm_nested_memslots), GFP_KERNEL_ACCOUNT);
	if (!slots)
		return NULL;

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++)
		slots->id_to_index[i] = -1;

	return slots;
}

static struct kvm_memory_slot *__get_memslot(struct kvm_nested_memslots *slots, short slot_id)
{
	short i;

	if (!slots)
		return NULL;

	if (slot_id >= KVM_MEM_SLOTS_NUM || slot_id < 0)
		return NULL;

	i = slots->id_to_index[slot_id];
	if (i < 0)
		return NULL;
	return &slots->memslots[i];
}

static const struct kvm_memory_slot *get_memslot(struct kvm_nested_memslots *slots, short slot_id)
{
	return __get_memslot(slots, slot_id);
}

static void kvmppc_free_memslot_rmap(struct kvm_nested_memslots *slots, short slot_id)
{
	struct kvm_memory_slot *slot = __get_memslot(slots, slot_id);

	if (!slot || !slot->arch.rmap)
		return;
	vfree(slot->arch.rmap);
	slot->arch.rmap = NULL;
}

void kvmppc_free_nested_slots(struct kvm_nested_guest *nested_guest)
{
	struct kvm_memory_slot *memslot;
	struct kvm_nested_memslots *slots;

	if (!nested_guest)
		return;

	slots = nested_guest->memslots;

	mutex_lock(&nested_guest->slots_lock);
	kvm_for_each_memslot(memslot, slots) {
		kvmppc_free_memslot_rmap(slots, memslot->id);
	}
	mutex_unlock(&nested_guest->slots_lock);
	kvfree(slots);
}

/* Move this memslot to the end of the list and erase it. The caller
 * might use the extra space to hold another memslot. */
static void __delete_memslot(struct kvm_nested_memslots *slots, const struct kvm_memory_slot *memslot)
{
	short id = memslot->id;
	int i;

	for (i = slots->id_to_index[id]; i < slots->used_slots - 1; i++) {
		slots->memslots[i] = slots->memslots[i + 1];
		slots->id_to_index[slots->memslots[i].id] = i;
	}

	slots->memslots[i] = *memslot;
	memset(__get_memslot(slots, i), 0, sizeof(*memslot));
	slots->id_to_index[id] = -1;
	slots->used_slots--;

	WARN_ON(slots->used_slots < 0);
}

/* Move all memslots after 'pos' one position forward and insert the
 * memslot. */
static void __insert_memslot(struct kvm_nested_memslots *slots, struct kvm_memory_slot *memslot, int pos)
{
	int i;

	for (i = slots->used_slots; i > pos; i--) {
		slots->memslots[i] = slots->memslots[i - 1];
		slots->id_to_index[slots->memslots[i].id] = i;
	}

	slots->memslots[pos] = *memslot;
	slots->id_to_index[memslot->id] = pos;
	slots->used_slots++;

	WARN_ON(slots->used_slots > KVM_MEM_SLOTS_NUM);
}

/*
 * Finds the position of the new slot in the sorted slots array
 * disallowing gfn overlaps.
 *
 * If the slot is being moved, take its future deletion into
 * consideration.
 */
static int __find_memslot_position(struct kvm_nested_memslots *slots,
				   struct kvm_memory_slot *new,
				   bool moving)
{
	struct kvm_memory_slot *tmp;
	int i, pos;

	for (i = 0, pos = 0; i < slots->used_slots; i++, pos++) {
		tmp = &slots->memslots[i];

		/* new goes before tmp */
		if (new->base_gfn >= tmp->base_gfn + tmp->npages) {
			break;
		}

		/* new goes after tmp */
		if (new->base_gfn + new->npages <= tmp->base_gfn) {
			/* walked past the slot we're trying to move */
			if (moving && new->id == tmp->id)
				pos--;
			continue;
		}

		/* overlap */
		return -1;
	}

	return pos;
}

static int nested_memslots_cmp(const void *key, const void *elt)
{
	gfn_t *gfn = (gfn_t *)key;
	struct kvm_memory_slot *memslot = (struct kvm_memory_slot *)elt;

	if (*gfn >= memslot->base_gfn + memslot->npages)
		return -1;
	if (*gfn < memslot->base_gfn)
		return 1;
	return 0;
}

static struct kvm_memory_slot *gfn_to_nested_memslot(struct kvm_nested_memslots *slots, gfn_t gfn)
{
	return bsearch(&gfn, slots->memslots, ARRAY_SIZE(slots->memslots),
		       sizeof(struct kvm_memory_slot), nested_memslots_cmp);
}

static int update_nested_slots(struct kvm_nested_guest *gp,
			       const struct kvm_memory_slot *old,
			       struct kvm_memory_slot *new)
{
	int pos;
	bool is_move_op = !!old;

	if (!gp || !gp->memslots || (!old && !new))
		return -EINVAL;

	if (!is_move_op && gp->memslots->used_slots >= KVM_MEM_SLOTS_NUM)
		return -EINVAL;

	if (new) {
		pos = __find_memslot_position(gp->memslots, new, is_move_op);
		if (pos < 0)
			return -EEXIST;

		new->arch.rmap = vzalloc(array_size(new->npages,
						    sizeof(*new->arch.rmap)));
		if (!new->arch.rmap)
			return -ENOMEM;
	}

	if (old) {
		kvmppc_free_memslot_rmap(gp->memslots, old->id);
		__delete_memslot(gp->memslots, old);
	}
	if (new)
		__insert_memslot(gp->memslots, new, pos);

	return 0;
}

static int kvmppc_insert_nested_memslot(struct kvm_nested_guest *nested_guest, struct kvm_memory_slot *new)
{
	const struct kvm_memory_slot *old;
	int r;

	if (!new || !nested_guest)
		return -EINVAL;

	mutex_lock(&nested_guest->slots_lock);

	old = get_memslot(nested_guest->memslots, new->id);
	r = update_nested_slots(nested_guest, old, new);

	mutex_unlock(&nested_guest->slots_lock);
	return r;
}

static int kvmppc_remove_nested_memslot(struct kvm_nested_guest *nested_guest, short slot_id)
{
	const struct kvm_memory_slot *old;
	int r;

	if (!nested_guest)
		return -EINVAL;

	mutex_lock(&nested_guest->slots_lock);

	old = get_memslot(nested_guest->memslots, slot_id);
	if (!old)
		return -EINVAL;

	r = update_nested_slots(nested_guest, old, NULL);

	mutex_unlock(&nested_guest->slots_lock);
	return r;
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
	struct kvm_memory_slot new;
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

	new.base_gfn = gpa >> PAGE_SHIFT;
	new.npages = nbytes >> PAGE_SHIFT;
	new.id = slot_id;
	new.flags = 0;

	r = kvmppc_insert_nested_memslot(nested_guest, &new);
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
	unsigned long ret = U_SUCCESS;
	int r;

	vcpu_debug(vcpu, "%s lpid=%d slot_id=%d", __func__, lpid, slot_id);

	if (slot_id >= KVM_MEM_SLOTS_NUM)
		return U_P2;

	nested_guest = kvmhv_get_nested(vcpu->kvm, lpid, false);
	if (!nested_guest)
		return U_PARAMETER;

	r = kvmppc_remove_nested_memslot(nested_guest, slot_id);
	if (r < 0)
		ret = U_P2;

	kvmhv_put_nested(nested_guest);
	return ret;
}

static unsigned long kvmppc_uv_page_in(struct kvm_vcpu *vcpu,
				       struct kvm_nested_guest *gp,
				       gpa_t gpa, gpa_t n_gpa,
				       struct kvm_memory_slot *memslot,
				       struct kvm_memory_slot *n_memslot,
				       unsigned long page_shift)
{
	struct kvm *kvm = vcpu->kvm;
	pte_t pte, *ptep;
	struct rmap_nested *n_rmap;
	unsigned long mmu_seq, *rmapp;
	gfn_t gfn, n_gfn;
	int r;


	gfn = gpa >> PAGE_SHIFT;
	n_gfn = n_gpa >> page_shift;

	/* Look for gra -> hra translation in our partition scoped tables for l1 */

	pte = __pte(0);
	spin_lock(&kvm->mmu_lock);
	ptep = find_kvm_secondary_pte(kvm, gpa, NULL);
	if (ptep)
		pte = *ptep;
	spin_unlock(&kvm->mmu_lock);

	if (!pte_present(pte)) {
		r = kvmppc_book3s_instantiate_page(vcpu, gpa, memslot, true,
						   false, &pte, NULL);
		if (r) {
			return U_P2;
		}
	}

	/* Unmap gra -> hra so that l1 cannot directly access l2's memory */

	spin_lock(&kvm->mmu_lock);
	kvm_unmap_radix(kvm, memslot, gfn);
	spin_unlock(&kvm->mmu_lock);

	/* Look for n_gra -> hra translation in the shadow page table for l2 */
	spin_lock(&kvm->mmu_lock);
	ptep = find_kvm_nested_guest_pte(kvm, gp->l1_lpid, n_gpa, NULL);
	spin_unlock(&kvm->mmu_lock);
	if (ptep) {
		if (pte_present(*ptep))
			return U_SUCCESS;
	}

	/* Insert new n_gra -> hra pte in the shadow page table for l2 */

	mmu_seq = kvm->mmu_notifier_seq;
	smp_rmb();

	n_rmap = kzalloc(sizeof(*n_rmap), GFP_KERNEL);
	if (!n_rmap) {
		printk_ratelimited(KERN_DEBUG "n_rmap\n");
		return U_NO_MEM;
	}
	n_rmap->rmap = (n_gpa & RMAP_NESTED_GPA_MASK) |
		(((unsigned long) gp->l1_lpid) << RMAP_NESTED_LPID_SHIFT);
	rmapp = &memslot->arch.rmap[gfn - memslot->base_gfn];
	r = kvmppc_create_pte(kvm, gp->shadow_pgtable, pte, n_gpa, 0,
			      mmu_seq, gp->shadow_lpid, rmapp, &n_rmap);
	kfree(n_rmap);
	if (r || !pte_present(pte))
		return U_BUSY;

	uv_gfn_set_state(&n_memslot->arch.rmap[n_gfn], GPF_SECURE);
	return U_SUCCESS;
}

static unsigned long kvmppc_uv_page_out(struct kvm_vcpu *vcpu,
					struct kvm_nested_guest *gp,
					gpa_t gpa, gpa_t n_gpa,
					struct kvm_memory_slot *memslot,
					struct kvm_memory_slot *n_memslot,
					unsigned long page_shift)
{
	struct kvm *kvm = vcpu->kvm;
	pte_t pte, *ptep;
	gfn_t gfn, n_gfn;
	enum uv_gpf_state gpf_state;
	int r;

	gfn = gpa >> PAGE_SHIFT;
	n_gfn = n_gpa >> page_shift;

	gpf_state = uv_gfn_state(n_memslot->arch.rmap[n_gfn]);

	if (gpf_state == GPF_HV_UNSHARED)
		return U_RETRY;

	if (gpf_state != GPF_SECURE)
		return U_P3;

	/* Invalidate shadow pte if it exists */

	kvmhv_invalidate_shadow_pte(vcpu, gp, n_gpa, NULL);

	/* Reinstate gra -> hra translation in our partition scoped tables for l1 */

	pte = __pte(0);
	spin_lock(&kvm->mmu_lock);
	ptep = find_kvm_secondary_pte(kvm, gpa, NULL);
	if (ptep)
		pte = *ptep;
	spin_unlock(&kvm->mmu_lock);

	if (!pte_present(pte)) {
		r = kvmppc_book3s_instantiate_page(vcpu, gpa, memslot, true,
						   false, &pte, NULL);
		if (r)
			return U_P2;
	}

	uv_gfn_set_state(&n_memslot->arch.rmap[n_gfn], GPF_PAGEDOUT);

	return U_SUCCESS;
}

/*
 * Handle the UV_PAGE_IN/OUT ucalls.
 * r4 = L1 lpid of secure guest
 * r5 = L1 gpa
 * r6 = L2 gpa
 * r7 = flags
 * r8 = order
 */
unsigned long kvmppc_uv_handle_paging(struct kvm_vcpu *vcpu, unsigned long op,
				      unsigned int lpid,
				      gpa_t gpa, gpa_t n_gpa,
				      unsigned long flags,
				      unsigned long order)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_nested_guest *gp;
	struct kvm_memory_slot *memslot, *n_memslot;
	unsigned long ret;
	gfn_t gfn, n_gfn;

	if (order != PAGE_SHIFT) {
		ret = U_P4;
		goto out;
	}

	gp = kvmhv_get_nested(kvm, lpid, false);
	if (!gp)
		return U_PARAMETER;

	gfn = gpa >> PAGE_SHIFT;
	memslot = gfn_to_memslot(kvm, gfn);
	if (!memslot || (memslot->flags & KVM_MEMSLOT_INVALID)) {
		ret = U_P2;
		goto out;
	}

	n_gfn = n_gpa >> order;
	n_memslot = gfn_to_nested_memslot(gp->memslots, n_gfn);
	if (!n_memslot || (n_memslot->flags & KVM_MEMSLOT_INVALID)) {
		ret = U_P3;
		goto out;
	}

	switch (op) {
	case UV_PAGE_IN:
		ret = kvmppc_uv_page_in(vcpu, gp, gpa, n_gpa,
					memslot, n_memslot, order);
		break;
	case UV_PAGE_OUT:
		ret = kvmppc_uv_page_out(vcpu, gp, gpa, n_gpa,
					 memslot, n_memslot, order);
		break;
	}

out:
	kvmhv_put_nested(gp);
	return ret;
}

/*
 * Handle the UV_PAGE_INVAL ucall.
 * r4 = L1 lpid of secure guest
 * r5 = L1 gpa
 * r8 = order
 */
unsigned long kvmppc_uv_invalidate(struct kvm_vcpu *vcpu, unsigned int lpid,
				   gpa_t n_gpa, unsigned long order)
{
	unsigned long ret = U_P2;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_memory_slot *n_memslot;
	struct kvm_nested_guest *gp;
	enum uv_gpf_state gpf_state;
	gfn_t n_gfn;

	if (order != PAGE_SHIFT)
		return U_P3;

	gp = kvmhv_get_nested(kvm, lpid, false);
	if (!gp)
		return U_PARAMETER;

	n_gfn = n_gpa >> order;
	n_memslot = gfn_to_nested_memslot(gp->memslots, n_gfn);
	if (!n_memslot || (n_memslot->flags & KVM_MEMSLOT_INVALID))
		goto out;

	gpf_state = uv_gfn_state(n_memslot->arch.rmap[n_gfn]);

//	vcpu_debug(vcpu, "%s lpid=%d gpa=%#llx n_gpa=%#lx state=%#x page_shift=%#lx", __func__, lpid, gpa, n_gpa, (int)gpf_state, order);

	switch (uv_gpf_state_generic(gpf_state)) {
	case GPF_SHARED:
		kvmhv_invalidate_shadow_pte(vcpu, gp, n_gpa, NULL);
		uv_gfn_set_state(&n_memslot->arch.rmap[n_gfn], gpf_state + 1);
		break;
	case GPF_SHARED_INV:
		break;
	default:
		goto out;
	}

	ret = U_SUCCESS;
out:
	kvmhv_put_nested(gp);
	return ret;
}
