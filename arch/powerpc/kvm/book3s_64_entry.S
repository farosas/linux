/* SPDX-License-Identifier: GPL-2.0-only */
#include <asm/asm-offsets.h>
#include <asm/cache.h>
#include <asm/code-patching-asm.h>
#include <asm/exception-64s.h>
#include <asm/export.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_book3s_asm.h>
#include <asm/ppc_asm.h>
#include <asm/reg.h>
#include <asm/ultravisor-api.h>

/*
 * These are branched to from interrupt handlers in exception-64s.S which set
 * IKVM_REAL or IKVM_VIRT, if HSTATE_IN_GUEST was found to be non-zero.
 */
.global	kvmppc_hcall
.balign IFETCH_ALIGN_BYTES
kvmppc_hcall:
	lbz	r10,HSTATE_IN_GUEST(r13)
	cmpwi	r10,KVM_GUEST_MODE_GUEST_HV_FAST
	beq	kvmppc_p9_exit_hcall
	ld	r10,PACA_EXGEN+EX_R13(r13)
	SET_SCRATCH0(r10)
	li	r10,0xc00
	li	r11,PACA_EXGEN
	b	1f

.global	kvmppc_interrupt
.balign IFETCH_ALIGN_BYTES
kvmppc_interrupt:
	std	r10,HSTATE_SCRATCH0(r13)
	lbz	r10,HSTATE_IN_GUEST(r13)
	cmpwi	r10,KVM_GUEST_MODE_GUEST_HV_FAST
	beq	kvmppc_p9_exit_interrupt
	ld	r10,HSTATE_SCRATCH0(r13)
	lbz	r11,HSTATE_IN_GUEST(r13)
	li	r11,PACA_EXGEN
	cmpdi	r10,0x200
	bgt+	1f
	li	r11,PACA_EXMC
	beq	1f
	li	r11,PACA_EXNMI
1:	add	r11,r11,r13

BEGIN_FTR_SECTION
	ld	r12,EX_CFAR(r11)
	std	r12,HSTATE_CFAR(r13)
END_FTR_SECTION_IFSET(CPU_FTR_CFAR)
	ld	r12,EX_CTR(r11)
	mtctr	r12
BEGIN_FTR_SECTION
	ld	r12,EX_PPR(r11)
	std	r12,HSTATE_PPR(r13)
END_FTR_SECTION_IFSET(CPU_FTR_HAS_PPR)
	ld	r12,EX_R12(r11)
	std	r12,HSTATE_SCRATCH0(r13)
	sldi	r12,r9,32
	or	r12,r12,r10
	ld	r9,EX_R9(r11)
	ld	r10,EX_R10(r11)
	ld	r11,EX_R11(r11)

	/*
	 * Hcalls and other interrupts come here after normalising register
	 * contents and save locations:
	 *
	 * R12		= (guest CR << 32) | interrupt vector
	 * R13		= PACA
	 * guest R12 saved in shadow HSTATE_SCRATCH0
	 * guest R13 saved in SPRN_SCRATCH0
	 */
	std	r9,HSTATE_SCRATCH2(r13)
	lbz	r9,HSTATE_IN_GUEST(r13)
	cmpwi	r9,KVM_GUEST_MODE_SKIP
	beq-	.Lmaybe_skip
.Lno_skip:
#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
#ifdef CONFIG_KVM_BOOK3S_PR_POSSIBLE
	cmpwi	r9,KVM_GUEST_MODE_GUEST
	beq	kvmppc_interrupt_pr
#endif
	b	kvmppc_interrupt_hv
#else
	b	kvmppc_interrupt_pr
#endif

/*
 * KVM uses a trick where it is running in MSR[HV]=1 mode in real-mode with the
 * guest MMU context loaded, and it sets KVM_GUEST_MODE_SKIP and enables
 * MSR[DR]=1 while leaving MSR[IR]=0, so it continues to fetch HV instructions
 * but loads and stores will access the guest context. This is used to load
 * the faulting instruction without walking page tables.
 *
 * However the guest context may not be able to translate, or it may cause a
 * machine check or other issue, which will result in a fault in the host
 * (even with KVM-HV).
 *
 * These faults are caught here and if the fault was (or was likely) due to
 * that load, then we just return with the PC advanced +4 and skip the load,
 * which then goes via the slow path.
 */
.Lmaybe_skip:
	cmpwi	r12,BOOK3S_INTERRUPT_MACHINE_CHECK
	beq	1f
	cmpwi	r12,BOOK3S_INTERRUPT_DATA_STORAGE
	beq	1f
	cmpwi	r12,BOOK3S_INTERRUPT_DATA_SEGMENT
	beq	1f
#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
	/* HSRR interrupts have 2 added to trap vector */
	cmpwi	r12,BOOK3S_INTERRUPT_H_DATA_STORAGE | 0x2
	beq	2f
#endif
	b	.Lno_skip
1:	mfspr	r9,SPRN_SRR0
	addi	r9,r9,4
	mtspr	SPRN_SRR0,r9
	ld	r12,HSTATE_SCRATCH0(r13)
	ld	r9,HSTATE_SCRATCH2(r13)
	GET_SCRATCH0(r13)
	RFI_TO_KERNEL
#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
2:	mfspr	r9,SPRN_HSRR0
	addi	r9,r9,4
	mtspr	SPRN_HSRR0,r9
	ld	r12,HSTATE_SCRATCH0(r13)
	ld	r9,HSTATE_SCRATCH2(r13)
	GET_SCRATCH0(r13)
	HRFI_TO_KERNEL
#endif

/* Stack frame offsets for kvmppc_hv_entry */
#define SFS			208
#define STACK_SLOT_VCPU		(SFS-8)
#define STACK_SLOT_NVGPRS	(SFS-152)	/* 18 gprs */

/*
 * void kvmppc_p9_enter_guest(struct vcpu *vcpu);
 *
 * Enter the guest on a ISAv3.0 or later system where we have exactly
 * one vcpu per vcore, and both the host and guest are radix, and threads
 * are set to "indepdent mode".
 */
.balign	IFETCH_ALIGN_BYTES
_GLOBAL(kvmppc_p9_enter_guest)
EXPORT_SYMBOL_GPL(kvmppc_p9_enter_guest)
	mflr	r0
	std	r0,PPC_LR_STKOFF(r1)
	stdu	r1,-SFS(r1)

	std	r1,HSTATE_HOST_R1(r13)
	std	r3,STACK_SLOT_VCPU(r1)

	mfcr	r4
	stw	r4,SFS+8(r1)

	reg = 14
	.rept	18
	std	reg,STACK_SLOT_NVGPRS + ((reg - 14) * 8)(r1)
	reg = reg + 1
	.endr

	ld	r4,VCPU_LR(r3)
	mtlr	r4
	ld	r4,VCPU_CTR(r3)
	mtctr	r4
	ld	r4,VCPU_XER(r3)
	mtspr	SPRN_XER,r4

	ld	r1,VCPU_CR(r3)

BEGIN_FTR_SECTION
	ld	r4,VCPU_CFAR(r3)
	mtspr	SPRN_CFAR,r4
END_FTR_SECTION_IFSET(CPU_FTR_CFAR)
BEGIN_FTR_SECTION
	ld	r4,VCPU_PPR(r3)
	mtspr	SPRN_PPR,r4
END_FTR_SECTION_IFSET(CPU_FTR_HAS_PPR)

	reg = 4
	.rept	28
	ld	reg,__VCPU_GPR(reg)(r3)
	reg = reg + 1
	.endr

	ld	r4,VCPU_KVM(r3)
	lbz	r4,KVM_SECURE_GUEST(r4)
	cmpdi	r4,0
	ld	r4,VCPU_GPR(R4)(r3)
	bne	.Lret_to_ultra

	mtcr	r1

	ld	r0,VCPU_GPR(R0)(r3)
	ld	r1,VCPU_GPR(R1)(r3)
	ld	r2,VCPU_GPR(R2)(r3)
	ld	r3,VCPU_GPR(R3)(r3)

	HRFI_TO_GUEST
	b	.

	/*
	 * Use UV_RETURN ultracall to return control back to the Ultravisor
	 * after processing an hypercall or interrupt that was forwarded
	 * (a.k.a. reflected) to the Hypervisor.
	 *
	 * All registers have already been reloaded except the ucall requires:
	 *   R0 = hcall result
	 *   R2 = SRR1, so UV can detect a synthesized interrupt (if any)
	 *   R3 = UV_RETURN
	 */
.Lret_to_ultra:
	mtcr	r1
	ld	r1,VCPU_GPR(R1)(r3)

	ld	r0,VCPU_GPR(R3)(r3)
	mfspr	r2,SPRN_SRR1
	LOAD_REG_IMMEDIATE(r3, UV_RETURN)
	sc	2

/*
 * kvmppc_p9_exit_hcall and kvmppc_p9_exit_interrupt are branched to from
 * above if the interrupt was taken for a guest that was entered via
 * kvmppc_p9_enter_guest().
 *
 * This code recovers the host stack and vcpu pointer, saves all GPRs and
 * CR, LR, CTR, XER as well as guest MSR and NIA into the VCPU, then re-
 * establishes the host stack and registers to return from  the
 * kvmppc_p9_enter_guest() function.
 */
.balign	IFETCH_ALIGN_BYTES
kvmppc_p9_exit_hcall:
	mfspr	r11,SPRN_SRR0
	mfspr	r12,SPRN_SRR1
	li	r10,0xc00
	std	r10,HSTATE_SCRATCH0(r13)

.balign	IFETCH_ALIGN_BYTES
kvmppc_p9_exit_interrupt:
	std     r1,HSTATE_SCRATCH1(r13)
	std     r3,HSTATE_SCRATCH2(r13)
	ld	r1,HSTATE_HOST_R1(r13)
	ld	r3,STACK_SLOT_VCPU(r1)

	std	r9,VCPU_CR(r3)

1:
	std	r11,VCPU_PC(r3)
	std	r12,VCPU_MSR(r3)

	reg = 14
	.rept	18
	std	reg,__VCPU_GPR(reg)(r3)
	reg = reg + 1
	.endr

	/* r1, r3, r9-r13 are saved to vcpu by C code */
	std	r0,VCPU_GPR(R0)(r3)
	std	r2,VCPU_GPR(R2)(r3)
	reg = 4
	.rept	5
	std	reg,__VCPU_GPR(reg)(r3)
	reg = reg + 1
	.endr

	ld	r2,PACATOC(r13)

	mflr	r4
	std	r4,VCPU_LR(r3)
	mfspr	r4,SPRN_XER
	std	r4,VCPU_XER(r3)

	reg = 14
	.rept	18
	ld	reg,STACK_SLOT_NVGPRS + ((reg - 14) * 8)(r1)
	reg = reg + 1
	.endr

	lwz	r4,SFS+8(r1)
	mtcr	r4

	/*
	 * Flush the link stack here, before executing the first blr on the
	 * way out of the guest.
	 *
	 * The link stack won't match coming out of the guest anyway so the
	 * only cost is the flush itself. The call clobbers r0.
	 */
1:	nop
	patch_site 1b patch__call_kvm_flush_link_stack_2

	addi	r1,r1,SFS
	ld	r0,PPC_LR_STKOFF(r1)
	mtlr	r0
	blr
