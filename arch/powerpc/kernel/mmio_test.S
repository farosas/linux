#include <asm/ppc_asm.h>

_GLOBAL(lq_test)
	std	r3,0(r3)
	ld	r5,mmio_test_data@got(r2)
	std	r5,8(r3)
//	ld	r14,0(r3)
//	ld	r14,8(r3)
	lq	r14,0(r3)
	blr
.p2align 4
mmio_test_data:
	.long	0xdeadbeef
	.long	0x8badf00d
	.long	0x1337c0de
	.long	0x01abcdef
