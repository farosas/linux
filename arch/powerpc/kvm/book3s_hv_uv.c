// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Fabiano Rosas, IBM Corp. <farosas@linux.ibm.com>
 *
 * Description: KVM functions specific to emulating an ultravisor in
 * hypervisor mode on Book3S processors (specifically POWER9 and later).
 */

#include <linux/kvm_host.h>

#include <asm/kvm_ppc.h>
#include <asm/ultravisor-api.h>

/*
 * L1 code currently only supports 64k pages in L2. See "Notes on page
 * size" at book3s_hv_uvmem.c
 */
#define L2_PAGE_SHIFT 16
#define L2_PAGE_SIZE (1ULL << L2_PAGE_SHIFT)


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
