/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_KVM_BOOK3S_UVMEM_H__
#define __ASM_KVM_BOOK3S_UVMEM_H__

struct kvm_nested_memslots;
struct kvm_nested_guest;

#ifdef CONFIG_PPC_UV
int kvmppc_uvmem_init(void);
void kvmppc_uvmem_free(void);
bool kvmppc_uvmem_available(void);
int kvmppc_uvmem_slot_init(struct kvm *kvm, const struct kvm_memory_slot *slot);
void kvmppc_uvmem_slot_free(struct kvm *kvm,
			    const struct kvm_memory_slot *slot);
unsigned long kvmppc_h_svm_page_in(struct kvm *kvm,
				   unsigned long gra,
				   unsigned long flags,
				   unsigned long page_shift);
unsigned long kvmppc_h_svm_page_out(struct kvm *kvm,
				    unsigned long gra,
				    unsigned long flags,
				    unsigned long page_shift);
unsigned long kvmppc_h_svm_init_start(struct kvm *kvm);
unsigned long kvmppc_h_svm_init_done(struct kvm *kvm);
int kvmppc_send_page_to_uv(struct kvm *kvm, unsigned long gfn);
unsigned long kvmppc_h_svm_init_abort(struct kvm *kvm);
void kvmppc_uvmem_drop_pages(const struct kvm_memory_slot *free,
			     struct kvm *kvm, bool skip_page_out);

struct kvm_nested_memslots *kvmppc_alloc_nested_slots(void);
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
#else
static inline int kvmppc_uvmem_init(void)
{
	return 0;
}

static inline void kvmppc_uvmem_free(void) { }

static inline bool kvmppc_uvmem_available(void)
{
	return false;
}

static inline int
kvmppc_uvmem_slot_init(struct kvm *kvm, const struct kvm_memory_slot *slot)
{
	return 0;
}

static inline void
kvmppc_uvmem_slot_free(struct kvm *kvm, const struct kvm_memory_slot *slot) { }

static inline unsigned long
kvmppc_h_svm_page_in(struct kvm *kvm, unsigned long gra,
		     unsigned long flags, unsigned long page_shift)
{
	return H_UNSUPPORTED;
}

static inline unsigned long
kvmppc_h_svm_page_out(struct kvm *kvm, unsigned long gra,
		      unsigned long flags, unsigned long page_shift)
{
	return H_UNSUPPORTED;
}

static inline unsigned long kvmppc_h_svm_init_start(struct kvm *kvm)
{
	return H_UNSUPPORTED;
}

static inline unsigned long kvmppc_h_svm_init_done(struct kvm *kvm)
{
	return H_UNSUPPORTED;
}

static inline unsigned long kvmppc_h_svm_init_abort(struct kvm *kvm)
{
	return H_UNSUPPORTED;
}

static inline int kvmppc_send_page_to_uv(struct kvm *kvm, unsigned long gfn)
{
	return -EFAULT;
}

static inline void
kvmppc_uvmem_drop_pages(const struct kvm_memory_slot *free,
			struct kvm *kvm, bool skip_page_out) { }

static inline unsigned long kvmppc_uv_esm(void)
{
	return U_FUNCTION;
}

struct inline kvm_nested_memslots *kvmppc_alloc_nested_slots(void)
{
	return NULL;
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

#endif /* CONFIG_PPC_UV */
#endif /* __ASM_KVM_BOOK3S_UVMEM_H__ */
