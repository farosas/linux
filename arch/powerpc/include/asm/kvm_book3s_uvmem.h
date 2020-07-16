/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_KVM_BOOK3S_UVMEM_H__
#define __ASM_KVM_BOOK3S_UVMEM_H__

typedef int (*kvm_vm_thread_fn_t)(struct kvm *kvm, uintptr_t data);
#ifdef CONFIG_PPC_UV

struct ucall_worker {
	struct task_struct *thread;
	kvm_vm_thread_fn_t thread_fn;

	struct completion step_done;
	struct completion hcall_done;

	struct kvm_vcpu *vcpu;
	bool in_progress;
	unsigned long ret;
};

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

unsigned long kvmppc_ucall_do_work(struct kvm_vcpu *vcpu, struct ucall_worker **w, kvm_vm_thread_fn_t);
int kvmppc_uv_esm_work_fn(struct kvm *kvm, uintptr_t thread_data);
struct kvm_nested_memslots *kvmppc_alloc_nested_slots(size_t size);
void kvmppc_free_nested_slots(struct kvm_nested_memslots *slots);
unsigned long kvmppc_uv_register_memslot(struct kvm_vcpu *vcpu,
					 unsigned int lpid,
					 gpa_t gpa,
					 unsigned long nbytes,
					 unsigned long flags,
					 short slot_id);
unsigned long kvmppc_uv_unregister_memslot(struct kvm_vcpu *vcpu, unsigned int lpid, short slot_id);
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

static inline unsigned long kvmppc_ucall_do_work(struct kvm_vcpu *vcpu, struct ucall_worker **w,
						 kvm_vm_thread_fn_t work_fn)
{
	return U_FUNCTION;
}

static inline int kvmppc_uv_esm_work_fn(struct kvm *kvm, uintptr_t thread_data)
{
	return 0;
}

struct kvm_nested_memslots *kvmppc_alloc_nested_slots(size_t size)
{
	return NULL;
}

void kvmppc_free_nested_slots(struct kvm_nested_memslots *slots)
{
}

static unsigned long kvmppc_uv_register_memslot(struct kvm_vcpu *vcpu,
					 unsigned int lpid,
					 gpa_t gpa,
					 unsigned long nbytes,
					 unsigned long flags,
					 short slot_id)
{
	return U_FUNCTION;
}

static unsigned long kvmppc_uv_unregister_memslot(struct kvm_vcpu *vcpu, unsigned int lpid, short slot_id)
{
	return U_FUNCTION;
}

#endif /* CONFIG_PPC_UV */
#endif /* __ASM_KVM_BOOK3S_UVMEM_H__ */
