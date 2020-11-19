/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_KVM_BOOK3S_UV_H__
#define __ASM_KVM_BOOK3S_UV_H__

#include <asm/ultravisor-api.h>

struct kvm_nested_guest;
struct kvm_nested_memslots;

#ifdef CONFIG_PPC_UV_EMULATE

enum svm_state {
	SVM_SECURE = 1,
	SVM_ABORT,
};

long int kvmppc_uv_handle_exit(struct kvm_vcpu *vcpu, long int r);
int kvmppc_uv_init(struct kvm_nested_guest *gp);
void kvmppc_uv_release(struct kvm_nested_guest *gp);
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
bool uv_in_progress(struct kvm_vcpu *vcpu);
int kvmppc_uv_page_fault(struct kvm_nested_guest *gp, unsigned long ea, unsigned long n_gpa);
#else
struct uv_worker;

static inline long int kvmppc_uv_handle_exit(struct kvm_vcpu *vcpu, long int r)
{
	return 0;
}

static inline int kvmppc_uv_init(struct kvm_nested_guest *gp)
{
	return 0;
}

static inline void kvmppc_uv_release(struct kvm_nested_guest *gp)
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

static inline unsigned long kvmppc_uv_invalidate(struct kvm_vcpu *vcpu, unsigned int lpid, gpa_t n_gpa,
						 unsigned long order)
{
	return U_FUNCTION;
}

static inline bool uv_in_progress(struct kvm_vcpu *vcpu)
{
	return false;

static inline int kvmppc_uv_page_fault(struct kvm_nested_guest *gp, unsigned long ea, unsigned long n_gpa)
{
	return 0;
}

#endif /* CONFIG_PPC_UV_EMULATE */
#endif /* __ASM_KVM_BOOK3S_UV_H__ */
