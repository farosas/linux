/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_KVM_BOOK3S_UV_H__
#define __ASM_KVM_BOOK3S_UV_H__

#include <asm/ultravisor-api.h>

#ifdef CONFIG_PPC_UV_EMULATE

long int kvmppc_uv_handle_exit(struct kvm_vcpu *vcpu, long int r);
unsigned long kvmppc_uv_register_memslot(void);
unsigned long kvmppc_uv_unregister_memslot(void);

#else

static inline long int kvmppc_uv_handle_exit(struct kvm_vcpu *vcpu, long int r)
{
	return 0;
}

static inline unsigned long kvmppc_uv_register_memslot(void)
{
       return U_FUNCTION;
}

static inline unsigned long kvmppc_uv_unregister_memslot(void)
{
       return U_FUNCTION;
}

#endif /* CONFIG_PPC_UV_EMULATE */
#endif /* __ASM_KVM_BOOK3S_UV_H__ */
