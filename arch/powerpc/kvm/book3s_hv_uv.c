// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Fabiano Rosas, IBM Corp. <farosas@linux.ibm.com>
 *
 * Description: KVM functions specific to emulating an ultravisor in
 * hypervisor mode on Book3S processors (specifically POWER9 and later).
 */

#include <linux/kvm_host.h>


static unsigned long kvmppc_uv_esm(void)
{
       return U_UNSUPPORTED;
}

static unsigned long kvmppc_uv_register_memslot(void)
{
       return U_UNSUPPORTED;
}

static unsigned long kvmppc_uv_unregister_memslot(void)
{
       return U_UNSUPPORTED;
}

/* Handles ultracalls issued by the nested guest */
static long int kvmppc_do_ucall(struct kvm_vcpu *vcpu, unsigned long opcode)
{
       unsigned long ret = U_FUNCTION;
       unsigned long opcode = kvmppc_get_gpr(vcpu, 3);

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
		return kvmppc_do_ucall(vcpu, opcode);
	}

	return r;
}
