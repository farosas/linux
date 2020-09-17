/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_KVM_BOOK3S_UV_H__
#define __ASM_KVM_BOOK3S_UV_H__

#include <asm/ultravisor-api.h>

struct kvm_nested_guest;
struct kvm_nested_memslots;

#ifdef CONFIG_PPC_UV_EMULATE
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

enum svm_state {
	SVM_SECURE = 1,
	SVM_ABORT,
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

int kvmppc_init_nested_slots(struct kvm_nested_guest *gp);
void kvmppc_free_nested_slots(struct kvm_nested_guest *nested_guest);
unsigned long kvmppc_uv_esm(void);
unsigned long kvmppc_uv_register_memslot(struct kvm_vcpu *vcpu,
					 unsigned int lpid,
					 gpa_t gpa,
					 unsigned long nbytes,
					 unsigned long flags,
					 short slot_id);
unsigned long kvmppc_uv_unregister_memslot(struct kvm_vcpu *vcpu, unsigned int lpid, short slot_id);
unsigned long kvmppc_uv_handle_paging(struct kvm_vcpu *vcpu, unsigned long op,
				      unsigned int lpid, gpa_t gpa, gpa_t n_gpa,
				      unsigned long flags, unsigned long order);
unsigned long kvmppc_uv_invalidate(struct kvm_vcpu *vcpu, unsigned int lpid, gpa_t n_gpa,
				   unsigned long order);
long int kvmppc_uv_handle_exit(struct kvm_vcpu *vcpu, long int r);
int kvmppc_uv_page_fault(struct kvm_nested_guest *gp, unsigned long ea, unsigned long n_gpa);
#else
struct uv_worker;

static inline int kvmppc_init_nested_slots(struct kvm_nested_guest *gp)
{
	return 0;
}

static inline void kvmppc_free_nested_slots(struct kvm_nested_guest *nested_guest)
{
}

static inline unsigned long kvmppc_uv_register_memslot(struct kvm_vcpu *vcpu,
						       unsigned int lpid,
						       gpa_t gpa,
						       unsigned long nbytes,
						       unsigned long flags,
						       short slot_id)
{
	return U_FUNCTION;
}

static inline unsigned long kvmppc_uv_unregister_memslot(struct kvm_vcpu *vcpu, unsigned int lpid, short slot_id)
{
	return U_FUNCTION;
}

static inline unsigned long kvmppc_uv_handle_paging(struct kvm_vcpu *vcpu, unsigned long op,
						    unsigned int lpid, gpa_t gpa, gpa_t n_gpa,
						    unsigned long flags, unsigned long order)
{
	return U_FUNCTION;
}

static inline unsigned long kvmppc_uv_invalidate(struct kvm_vcpu *vcpu, unsigned int lpid,
						 gpa_t n_gpa, unsigned long order)
{
	return U_FUNCTION;
}

static inline long int kvmppc_uv_handle_exit(struct kvm_vcpu *vcpu, long int r)
{
	return 0;
}

static inline int kvmppc_uv_page_fault(struct kvm_nested_guest *gp, unsigned long ea, unsigned long n_gpa)
{
	return 0;
}

#endif /* CONFIG_PPC_UV_EMULATE */
#endif /* __ASM_KVM_BOOK3S_UV_H__ */
