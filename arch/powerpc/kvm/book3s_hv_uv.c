// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Fabiano Rosas, IBM Corp. <farosas@linux.ibm.com>
 *
 * Description: KVM functions specific to emulating an ultravisor in
 * hypervisor mode on Book3S processors (specifically POWER9 and later).
 */

#include <linux/kvm_host.h>
#include <linux/bsearch.h>

#include <asm/kvm_ppc.h>
#include <asm/ultravisor-api.h>

/*
 * L1 code currently only supports 64k pages in L2. See "Notes on page
 * size" at book3s_hv_uvmem.c
 */
#define L2_PAGE_SHIFT 16
#define L2_PAGE_SIZE (1ULL << L2_PAGE_SHIFT)

enum svm_state {
	SVM_SECURE = 1,
	SVM_ABORT,
};

enum uv_gpf_state {
	GPF_SECURE,
	GPF_PAGEDOUT,
};

static bool uv_rmap_valid(unsigned long rmap)
{
	return ((rmap & KVMPPC_RMAP_TYPE_MASK) == KVMPPC_RMAP_UV_GFN);
}

static enum uv_gpf_state uv_gpf_state(unsigned long rmap)
{
	if (uv_rmap_valid(rmap))
		return (rmap & KVMPPC_RMAP_UV_GPF_STATE_MASK) >> KVMPPC_RMAP_UV_GPF_STATE_SHIFT;
	return GPF_SECURE;
}

static void uv_rmap_set_state(unsigned long *rmap, enum uv_gpf_state state)
{
	unsigned long s = state;

	*rmap = KVMPPC_RMAP_UV_GFN | (*rmap & ~KVMPPC_RMAP_UV_GPF_STATE_MASK) |
		(s << KVMPPC_RMAP_UV_GPF_STATE_SHIFT);
}

static bool uv_gfn_paged_in(unsigned long rmap)
{
	return (uv_rmap_valid(rmap) && test_bit(KVMPPC_RMAP_UV_PAGED_IN_BIT, &rmap));
}

static void uv_gfn_set_paged_in(unsigned long *rmap)
{
	*rmap |= KVMPPC_RMAP_UV_GFN;
	set_bit(KVMPPC_RMAP_UV_PAGED_IN_BIT, rmap);
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

/* called with rmap lock taken */
static unsigned long kvmppc_uv_page_in(struct kvm_vcpu *vcpu,
				       struct kvm_nested_guest *gp,
				       gpa_t gpa, gpa_t n_gpa,
				       struct kvm_memory_slot *memslot,
				       struct kvm_memory_slot *n_memslot,
				       unsigned long *rmapp,
				       unsigned long page_shift)
{
	struct kvm *kvm = vcpu->kvm;
	pte_t pte, *ptep;
	unsigned long mmu_seq, *l1_rmapp;
	enum uv_gpf_state state;
	gfn_t gfn, n_gfn;
	int level;
	long int r;

	gfn = gpa >> PAGE_SHIFT;
	n_gfn = n_gpa >> page_shift;
	state = uv_gpf_state(*rmapp);

	/* Look for gra -> hra translation in our partition scoped tables for l1 */
	mmu_seq = kvm->mmu_notifier_seq;
	smp_rmb();

	pte = __pte(0);
	spin_lock(&kvm->mmu_lock);
	ptep = find_kvm_secondary_pte(kvm, gpa, NULL);
	if (ptep)
		pte = *ptep;
	spin_unlock(&kvm->mmu_lock);

	if (!pte_present(pte)) {
		r = kvmppc_book3s_instantiate_page(vcpu, gpa, memslot, true,
						   false, &pte, NULL);
		if (r == -EAGAIN)
			return U_BUSY;
		if (r)
			return U_P2;
	}

	/* Unmap gra -> hra so that l1 cannot directly access l2's memory */

	spin_lock(&kvm->mmu_lock);
	kvm_unmap_radix(kvm, memslot, gfn);

	/* Look for n_gra -> hra translation in the shadow page table for l2 */

	ptep = find_kvm_nested_guest_pte(kvm, gp->l1_lpid, n_gpa, NULL);
	spin_unlock(&kvm->mmu_lock);
	if (ptep && pte_present(*ptep))
		goto out;

	/* Insert new n_gra -> hra pte in the shadow page table for l2 */

	level = kvmppc_radix_shift_to_level(page_shift);
	l1_rmapp = &memslot->arch.rmap[gfn - memslot->base_gfn];

	r = kvmhv_insert_shadow_pte(kvm, gp, pte, n_gpa, level, l1_rmapp, mmu_seq);

	if (r == -EAGAIN)
		return U_BUSY;
	if (r || !pte_present(pte))
		return U_BUSY;
out:
	uv_gfn_set_paged_in(rmapp);
	uv_rmap_set_state(rmapp, GPF_SECURE);


	return U_SUCCESS;
}

/* called with rmap lock taken */
static unsigned long kvmppc_uv_page_out(struct kvm_vcpu *vcpu,
					struct kvm_nested_guest *gp,
					gpa_t gpa, gpa_t n_gpa,
					struct kvm_memory_slot *memslot,
					struct kvm_memory_slot *n_memslot,
					unsigned long *rmapp,
					unsigned long page_shift)
{
	struct kvm *kvm = vcpu->kvm;
	pte_t pte, *ptep;
	gfn_t gfn, n_gfn;
	enum uv_gpf_state state;
	int r;

	gfn = gpa >> PAGE_SHIFT;
	n_gfn = n_gpa >> page_shift;
	state = uv_gpf_state(*rmapp);

	if (!uv_gfn_paged_in(*rmapp))
		return U_SUCCESS;

	vcpu_debug(vcpu, "%s gpa:%#llx ngpa:%#llx\n", __func__, gpa, n_gpa);

	if (state != GPF_SECURE)
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

	uv_rmap_set_state(rmapp, GPF_PAGEDOUT);

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
	unsigned long ret, *rmapp;
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

	rmapp = &n_memslot->arch.rmap[n_gfn];
	lock_rmap(rmapp);

	switch (op) {
	case UV_PAGE_IN:
		ret = kvmppc_uv_page_in(vcpu, gp, gpa, n_gpa,
					memslot, n_memslot, rmapp, order);
		break;
	case UV_PAGE_OUT:
		ret = kvmppc_uv_page_out(vcpu, gp, gpa, n_gpa,
					 memslot, n_memslot, rmapp, order);
		break;
	}

out:
	unlock_rmap(rmapp);
	kvmhv_put_nested(gp);
	return ret;
}

static unsigned long kvmppc_uv_esm(void)
{
	return U_UNSUPPORTED;
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
		ret = kvmppc_uv_esm();
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
