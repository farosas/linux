// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Fabiano Rosas, IBM Corp. <farosas@linux.ibm.com>
 *
 * Description: KVM functions specific to emulating an ultravisor in
 * hypervisor mode on Book3S processors (specifically POWER9 and later).
 */

#include <linux/kvm_host.h>
#include <linux/bsearch.h>
#include <linux/kthread.h>

#include <asm/kvm_ppc.h>
#include <asm/ultravisor-api.h>

/*
 * L1 code currently only supports 64k pages in L2. See "Notes on page
 * size" at book3s_hv_uvmem.c
 */
#define L2_PAGE_SHIFT 16
#define L2_PAGE_SIZE (1ULL << L2_PAGE_SHIFT)

typedef int (*kvm_vm_thread_fn_t)(struct kvm *kvm, uintptr_t data);

struct uv_worker {
	struct task_struct *thread;
	kvm_vm_thread_fn_t thread_fn;

	struct completion work_step_done;
	struct completion hcall_done;

	struct kvm_vcpu *vcpu;

	unsigned long opcode;
	bool in_progress;
	unsigned long ret;
};

enum uv_gpf_state {
	GPF_SECURE,
	GPF_PAGEDOUT,
	GPF_SHARED,
	GPF_SHARED_INV,
	GPF_SHARED_IMPLICIT,
	GPF_SHARED_IMPLICIT_INV,
	GPF_HV_SHARING,
	GPF_HV_SHARED,
	GPF_HV_SHARED_INV,
	GPF_HV_UNSHARING,
	GPF_HV_UNSHARING_INV,
	GPF_HV_UNSHARED,
	GPF_PSEUDO_SHARED,
	GPF_PSEUDO_SHARED_INV,
};

static inline enum uv_gpf_state uv_gpf_state_generic(enum uv_gpf_state state)
{
	switch (state) {
	case GPF_SHARED:
	case GPF_SHARED_IMPLICIT:
	case GPF_HV_SHARED:
	case GPF_HV_UNSHARING:
	case GPF_PSEUDO_SHARED:
		return GPF_SHARED;
	case GPF_SHARED_INV:
	case GPF_SHARED_IMPLICIT_INV:
	case GPF_HV_SHARED_INV:
	case GPF_HV_UNSHARING_INV:
	case GPF_PSEUDO_SHARED_INV:
		return GPF_SHARED_INV;
	default:
		return state;
	}
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
	*rmap = KVMPPC_RMAP_UV_GFN | (*rmap & ~KVMPPC_RMAP_UV_GPF_STATE_MASK) | state;
}

static struct uv_worker *kvmppc_uv_worker_init(struct kvm_vcpu *vcpu, kvm_vm_thread_fn_t fn, unsigned long opcode)
{
	struct uv_worker *worker;
	int r = 0;

	worker = kzalloc(sizeof(struct uv_worker), GFP_KERNEL);
	if (!worker)
		return NULL;

	init_completion(&worker->work_step_done);
	init_completion(&worker->hcall_done);

	worker->thread_fn = fn;

	/* These are for the worker function to consume. We could
	 * convert to a single pointer to include arbitrary data in
	 * the future */
	worker->vcpu = vcpu;
	worker->opcode = opcode;

	r = kvm_vm_create_worker_thread(vcpu->kvm, worker->thread_fn, (uintptr_t)worker, "kvm_uv_worker",
					&worker->thread);
	if (r) {
		kfree(worker);
		return NULL;
	}

	return worker;
}

static void kvmppc_uv_worker_wait(struct uv_worker *worker)
{
	int r;

	worker->ret = U_TOO_HARD;
	complete(&worker->work_step_done);
	r = wait_for_completion_killable(&worker->hcall_done);
	if (r == -ERESTARTSYS) {
		printk(KERN_DEBUG "worker killed\n");
	}

	reinit_completion(&worker->hcall_done);
}

static void __noreturn kvmppc_uv_worker_exit(struct uv_worker *worker, unsigned long ret)
{
	worker->ret = ret;
	worker->in_progress = false;
	complete_and_exit(&worker->work_step_done, 0);
}

static void __kvmppc_uv_worker_step(struct kvm_vcpu *vcpu, struct uv_worker *worker)
{
	int r;

	if (!worker->in_progress) {
		worker->in_progress = true;
		kthread_unpark(worker->thread);
	} else {
		reinit_completion(&worker->work_step_done);
		complete(&worker->hcall_done);
	}

	r = wait_for_completion_killable(&worker->work_step_done);
	if (r == -ERESTARTSYS) {
		printk(KERN_DEBUG "main thread killed\n");
		worker->ret = -EINTR;
		worker->in_progress = false;
	}
}

/*
 * This function is called to make progress with an ultracall in L0
 * that needs assistance from the nested hypervisor. The ucall handler
 * runs in a separate thread and does so in steps separated by
 * hypercall requests. Returns U_TOO_HARD while there is still work to
 * be done.
 */
static unsigned long kvmppc_uv_do_work(struct kvm_vcpu *vcpu, kvm_vm_thread_fn_t work_fn, unsigned long opcode)
{
	struct uv_worker *worker = vcpu->arch.uv_worker;
	unsigned long ret;

	if (!worker) {
		worker = kvmppc_uv_worker_init(vcpu, work_fn, opcode);
		if (!worker)
			return U_NO_MEM;
		vcpu->arch.uv_worker = worker;
	}

	__kvmppc_uv_worker_step(vcpu, worker);
	ret = worker->ret;

	if (!worker->in_progress) {
		kfree(worker);
		vcpu->arch.uv_worker = NULL;
	}

	return ret;
}

static bool uv_gfn_paged_in(unsigned long rmap_entry)
{
	return (uv_gfn_rmap_valid(rmap_entry) && test_bit(KVMPPC_RMAP_UV_PAGED_IN_BIT, &rmap_entry));
}

static void uv_gfn_set_paged_in(unsigned long *rmap_entry)
{
	*rmap_entry |= KVMPPC_RMAP_UV_GFN;
	set_bit(KVMPPC_RMAP_UV_PAGED_IN_BIT, rmap_entry);
}

static unsigned long hcall(struct kvm_vcpu *vcpu, unsigned long hcall, int nargs, ...)
{
	int i;
	va_list args;
	struct uv_worker *worker;

	worker = vcpu->arch.uv_worker;

	va_start(args, nargs);
	for (i = 0; i < nargs; ++i)
		kvmppc_set_gpr(vcpu, 4 + i, va_arg(args, unsigned long));
	va_end(args);

	/* Set the registers as if L2 was doing the hcall. */
	kvmppc_set_gpr(vcpu, 3, hcall);
	kvmppc_set_srr1(vcpu, kvmppc_get_srr1(vcpu) | MSR_S);
	vcpu->arch.trap = BOOK3S_INTERRUPT_SYSCALL;

	/* wait for L1 */
	kvmppc_uv_worker_wait(worker);

	return kvmppc_get_gpr(vcpu, 3);
}

int kvmppc_init_nested_slots(struct kvm_nested_guest *gp)
{
	struct kvm_nested_memslots *slots;
	int i;

	slots = kvzalloc(sizeof(struct kvm_nested_memslots), GFP_KERNEL_ACCOUNT);
	if (!slots)
		return -ENOMEM;

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++)
		slots->id_to_index[i] = -1;

	mutex_init(&gp->slots_lock);
	gp->memslots = slots;

	return 0;
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

void kvmppc_free_nested_slots(struct kvm_nested_guest *gp)
{
	struct kvm_memory_slot *memslot;
	struct kvm_nested_memslots *slots;

	if (!gp)
		return;

	slots = gp->memslots;

	mutex_lock(&gp->slots_lock);
	kvm_for_each_memslot(memslot, slots) {
		kvmppc_free_memslot_rmap(slots, memslot->id);
	}
	mutex_unlock(&gp->slots_lock);
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

static int kvmppc_insert_nested_memslot(struct kvm_nested_guest *gp, struct kvm_memory_slot *new)
{
	const struct kvm_memory_slot *old;
	int r;

	if (!new || !gp)
		return -EINVAL;

	mutex_lock(&gp->slots_lock);

	old = get_memslot(gp->memslots, new->id);
	r = update_nested_slots(gp, old, new);

	mutex_unlock(&gp->slots_lock);
	return r;
}

static int kvmppc_remove_nested_memslot(struct kvm_nested_guest *gp, short slot_id)
{
	const struct kvm_memory_slot *old;
	int r;

	if (!gp)
		return -EINVAL;

	mutex_lock(&gp->slots_lock);

	old = get_memslot(gp->memslots, slot_id);
	if (!old)
		return -EINVAL;

	r = update_nested_slots(gp, old, NULL);

	mutex_unlock(&gp->slots_lock);
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
	struct kvm_nested_guest *gp;
	struct kvm_memory_slot new;
	unsigned long ret = U_SUCCESS;
	int r = 0;

	vcpu_debug(vcpu, "%s lpid=%d gpa=%llx nbytes=%lx flags=%lx slot_id=%d", __func__,
		   lpid, gpa, nbytes, flags, slot_id);

	if (gpa & (L2_PAGE_SIZE - 1))
		return U_P2;

	if (!nbytes || gpa + nbytes < gpa)
		return U_P3;

	if (slot_id >= KVM_MEM_SLOTS_NUM)
		return U_P5;

	gp = kvmhv_get_nested(vcpu->kvm, lpid, false);
	if (!gp)
		return U_P4;

	new.base_gfn = gpa >> L2_PAGE_SHIFT;
	new.npages = nbytes >> L2_PAGE_SHIFT;
	new.id = slot_id;
	new.flags = 0;

	r = kvmppc_insert_nested_memslot(gp, &new);
	if (r < 0)
		ret = U_P2;

	kvmhv_put_nested(gp);
	return ret;
}

/*
 * Handle the UV_UNREGISTER_MEM_SLOT ucall.
 * r4 = L1 lpid of secure guest
 * r5 = memslot id
 */
unsigned long kvmppc_uv_unregister_memslot(struct kvm_vcpu *vcpu, unsigned int lpid, short slot_id)
{
	struct kvm_nested_guest *gp;
	unsigned long ret = U_SUCCESS;
	int r;

	vcpu_debug(vcpu, "%s lpid=%d slot_id=%d", __func__, lpid, slot_id);

	if (slot_id >= KVM_MEM_SLOTS_NUM)
		return U_P2;

	gp = kvmhv_get_nested(vcpu->kvm, lpid, false);
	if (!gp)
		return U_PARAMETER;

	r = kvmppc_remove_nested_memslot(gp, slot_id);
	if (r < 0)
		ret = U_P2;

	kvmhv_put_nested(gp);
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
	int r, level;
	enum uv_gpf_state gpf_state;

	gfn = gpa >> PAGE_SHIFT;
	n_gfn = n_gpa >> page_shift;
	gpf_state = uv_gfn_state(n_memslot->arch.rmap[n_gfn]);

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
		if (r)
			return U_P2;
	}

	/* Unmap gra -> hra so that l1 cannot directly access l2's memory */

	spin_lock(&kvm->mmu_lock);
	kvm_unmap_radix(kvm, memslot, gfn);
	spin_unlock(&kvm->mmu_lock);

	/* Look for n_gra -> hra translation in the shadow page table for l2 */
	spin_lock(&kvm->mmu_lock);
	ptep = find_kvm_nested_guest_pte(kvm, gp->l1_lpid, n_gpa, NULL);
	spin_unlock(&kvm->mmu_lock);
	if (ptep && pte_present(*ptep))
		return U_SUCCESS;

	/* Insert new n_gra -> hra pte in the shadow page table for l2 */

	mmu_seq = kvm->mmu_notifier_seq;
	smp_rmb();

	n_rmap = kzalloc(sizeof(*n_rmap), GFP_KERNEL);
	if (!n_rmap)
		return U_NO_MEM;
	n_rmap->rmap = (n_gpa & RMAP_NESTED_GPA_MASK) |
		(((unsigned long) gp->l1_lpid) << RMAP_NESTED_LPID_SHIFT);
	rmapp = &memslot->arch.rmap[gfn - memslot->base_gfn];

	level = (page_shift == PMD_SHIFT) ? 1 : 0;

	r = kvmppc_create_pte(kvm, gp->shadow_pgtable, pte, n_gpa, level,
			      mmu_seq, gp->shadow_lpid, rmapp, &n_rmap);
	kfree(n_rmap);
	if (r == -EAGAIN)
		return U_BUSY;
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

unsigned long kvmppc_page_in_hcall(struct kvm_vcpu *vcpu, gpa_t gpa, int type)
{
	return hcall(vcpu, H_SVM_PAGE_IN, 3, gpa, type, L2_PAGE_SHIFT);
}

static int kvmppc_page_in_from_hv(struct kvm_vcpu *vcpu, unsigned long *rmap, gfn_t start_gfn, unsigned long npages)
{
	unsigned long ret;
	gfn_t gfn;
	int r = 0;

	if (!npages)
		return -EINVAL;

	for (gfn = start_gfn; gfn < start_gfn + npages; gfn++) {

		if (uv_gfn_paged_in(rmap[gfn]) ||
		    uv_gfn_state(rmap[gfn]) != GPF_SECURE)
			continue;
		ret = kvmppc_page_in_hcall(vcpu, gfn_to_gpa(gfn), H_PAGE_IN_NONSHARED);
		if (ret != H_SUCCESS) {
			printk(KERN_DEBUG "%s failed ret=%#lx", __func__, ret);
			r = -1;
			break;
		}

		uv_gfn_set_paged_in(&rmap[gfn]);
	}

	return r;
}

static int kvmppc_page_in_from_hv_all(struct kvm_vcpu *vcpu, struct kvm_nested_guest *gp)
{
	struct kvm_memory_slot *memslot;
	int r;

	if (!gp)
		return -EINVAL;

	if (gp->svm_state == SVM_SECURE)
		return -EPERM;

	mutex_lock(&gp->slots_lock);
	kvm_for_each_memslot(memslot, gp->memslots) {
		r = kvmppc_page_in_from_hv(vcpu,
					   memslot->arch.rmap,
					   memslot->base_gfn,
					   memslot->npages);
		if (r)
			goto out;
	}
out:
	mutex_unlock(&gp->slots_lock);
	printk(KERN_DEBUG "%s ret=%d", __func__, r);
	return r;
}

/*
 * Handle the UV_ESM ucall.
 * r4 = secure guest's kernel base address
 * r5 = secure guest's firmware device tree address
 */
int kvmppc_uv_esm_work_fn(struct kvm *kvm, uintptr_t thread_data)
{
	struct uv_worker *worker = (struct uv_worker *)thread_data;
	struct kvm_vcpu *vcpu = worker->vcpu;
	unsigned long kbase = kvmppc_get_gpr(vcpu, 4);
	unsigned long fdt = kvmppc_get_gpr(vcpu, 5);
	// not documented
	unsigned long ret = U_FUNCTION;
	int r;

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

	ret = hcall(vcpu, H_SVM_INIT_START, 0);
	if (ret != H_SUCCESS)
		goto abort;

	r = kvmppc_page_in_from_hv_all(vcpu, vcpu->arch.nested);
	if (r) {
		printk(KERN_DEBUG "%s: page in all failed (%d)\n", __func__, r);
		goto abort;
	}

	ret = hcall(vcpu, H_SVM_INIT_DONE, 0);
	if (ret != H_SUCCESS)
		goto abort;

	vcpu->arch.nested->svm_state = SVM_SECURE;
	ret = U_SUCCESS;
out:
	kvmppc_uv_worker_exit(worker, ret);
abort:
	vcpu->arch.nested->svm_state = SVM_ABORT;

	/* H_SVM_INIT_ABORT returns H_PARAMETER on completion. */
	ret = hcall(vcpu, H_SVM_INIT_ABORT, 0);
	if (ret != H_PARAMETER)
		pr_err_ratelimited("KVM-UV: vm abortion did not complete\n");
	kvmppc_uv_worker_exit(worker, H_PARAMETER);
}

/*
 * Handles hypercalls issued by the nested guest when emulating an
 * ultravisor in a system without SMF. This includes what the nested
 * guest sees as ultracalls (sc 2 is handled by the hardware as sc 1).
 */
static long int kvmppc_uv_do_hcall(struct kvm_vcpu *vcpu, unsigned long opcode)
{
	unsigned long ret = U_FUNCTION;

	switch (opcode) {
	case UV_ESM:
		ret = kvmppc_uv_do_work(vcpu, kvmppc_uv_esm_work_fn, opcode);

		if (ret == U_TOO_HARD)
			return RESUME_HOST;

		if (ret == U_NO_MEM)
			return U_RETRY;
		break;
	default:
		return RESUME_HOST;
	}
	kvmppc_set_gpr(vcpu, 3, ret);
	return RESUME_GUEST;
}

long int kvmppc_uv_handle_exit(struct kvm_vcpu *vcpu, long int r)
{
	unsigned long opcode;

	if (vcpu->run->exit_reason == KVM_EXIT_PAPR_HCALL) {
		opcode = kvmppc_get_gpr(vcpu, 3);
		return kvmppc_uv_do_hcall(vcpu, opcode);
	}

	return r;
}
