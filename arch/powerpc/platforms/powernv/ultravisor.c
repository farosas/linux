// SPDX-License-Identifier: GPL-2.0
/*
 * Ultravisor high level interfaces
 *
 * Copyright 2019, IBM Corporation.
 *
 */
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/of_fdt.h>
#include <linux/of.h>
#include <linux/libfdt.h>
#include <linux/slab.h>

#include <asm/ultravisor.h>
#include <asm/firmware.h>
#include <asm/machdep.h>

#include "powernv.h"

static struct kobject *ultravisor_kobj;

int __init early_init_dt_scan_ultravisor(unsigned long node, const char *uname,
					 int depth, void *data)
{
	if (!of_flat_dt_is_compatible(node, "ibm,ultravisor"))
		return 0;

	powerpc_firmware_features |= FW_FEATURE_ULTRAVISOR;
	pr_debug("Ultravisor detected!\n");
	return 1;
}

static struct memcons *uv_memcons;

static ssize_t uv_msglog_read(struct file *file, struct kobject *kobj,
			      struct bin_attribute *bin_attr, char *to,
			      loff_t pos, size_t count)
{
	return memcons_copy(uv_memcons, to, pos, count);
}

static struct bin_attribute uv_msglog_attr = {
	.attr = {.name = "msglog", .mode = 0400},
	.read = uv_msglog_read
};

static int __init uv_init(void)
{
	struct device_node *node;

	if (!firmware_has_feature(FW_FEATURE_ULTRAVISOR))
		return 0;

	node = of_find_compatible_node(NULL, NULL, "ibm,uv-firmware");
	if (!node)
		return -ENODEV;

	uv_memcons = memcons_init(node, "memcons");
	if (!uv_memcons)
		return -ENOENT;

	uv_msglog_attr.size = memcons_get_size(uv_memcons);

	ultravisor_kobj = kobject_create_and_add("ultravisor", firmware_kobj);
	if (!ultravisor_kobj)
		return -ENOMEM;

	return sysfs_create_bin_file(ultravisor_kobj, &uv_msglog_attr);
}
machine_subsys_initcall(powernv, uv_init);

#ifdef DEBUG
#define FDT_ALIGN(x, a)	(((x) + (a) - 1) & ~((a) - 1))
static void uv_fdt_print(unsigned long *afdt)
{
	struct fdt_header *fdt;
	int i, rc;

	fdt = (struct fdt_header *) afdt;

	printk(KERN_INFO "%s\n", __func__);

	printk(KERN_INFO "magic 0x%x\n", fdt_magic(fdt));
	printk(KERN_INFO "totalsize 0x%x\n", fdt_totalsize(fdt));
	printk(KERN_INFO "off_dt_struct 0x%x\n", fdt_off_dt_struct(fdt));
	printk(KERN_INFO "off_dt_strings 0x%x\n", fdt_off_dt_strings(fdt));
	printk(KERN_INFO "off_mem_rsvmap 0x%x\n", fdt_off_mem_rsvmap(fdt));
	printk(KERN_INFO "version 0x%x\n", fdt_version(fdt));
	printk(KERN_INFO "last_comp_version 0x%x\n", fdt_last_comp_version(fdt));
	printk(KERN_INFO "boot_cpuid_phys 0x%x\n", fdt_boot_cpuid_phys(fdt));
	printk(KERN_INFO "size_dt_strings 0x%x\n", fdt_size_dt_strings(fdt));
	printk(KERN_INFO "size_dt_struct 0x%x\n", fdt_size_dt_struct(fdt));

	for (i = 0; i < fdt_num_mem_rsv(fdt); i++) {
		u64 addr, size;

		rc = fdt_get_mem_rsv(fdt, i, &addr, &size);
		if (rc) {
			printk(KERN_INFO " ERR %s\n", fdt_strerror(rc));
			return;
		}
		printk(KERN_INFO "  mem_rsv[%i] = %lx@%#lx\n",
		       i, (long)size, (long)addr);
	}

	if (fdt_off_mem_rsvmap(fdt) < FDT_ALIGN(sizeof(struct fdt_header), 8)) {
		printk(KERN_INFO "rsvmap not aligned\n");
	}

	if (fdt_off_dt_struct(fdt) <
			(fdt_off_mem_rsvmap(fdt) +
			 sizeof(struct fdt_reserve_entry))) {
		printk(KERN_INFO "dt_struct before rsvmap\n");
	}

	if (fdt_off_dt_strings(fdt) < (fdt_off_dt_struct(fdt) +
				fdt_size_dt_struct(fdt))) {
		printk(KERN_INFO "dt_strings before dt_struct\n");
	}

	if (fdt_totalsize(fdt) <
			(fdt_off_dt_strings(fdt) + fdt_size_dt_strings(fdt))) {
		printk(KERN_INFO "totalsize < size of dt_strings\n");
	}
	printk(KERN_INFO "%s end\n\n", __func__);
}
#endif

static u32 uv_fdt_get_cell(const struct fdt_property *prop, unsigned int i)
{
	if (prop->len >= (i + 1) * sizeof(u32))
		return fdt32_to_cpu(((const u32 *)prop->data)[i]);
	return 0;
}

static int uv_get_rma(unsigned long *fdt, u64 *rma)
{
	const struct fdt_property *prop;
	int prop_len;
	u64 base, size;
	int offset;

	offset = fdt_path_offset(fdt, "/memory@0");
	if (offset < 0)
		return -ENOENT;

	prop = fdt_get_property(fdt, offset, "reg", &prop_len);

	if (!prop || prop_len < 2 * sizeof(u64))
		return -ENOENT;

	base = ((u64)uv_fdt_get_cell(prop, 0) << 32) | uv_fdt_get_cell(prop, 1);
	size = ((u64)uv_fdt_get_cell(prop, 2) << 32) | uv_fdt_get_cell(prop, 3);

	if (base)
		return -EINVAL;

	/*
	 * RMA is capped at 768 MB to match what is done in
	 * prom_init.
	 */
	*rma = min(0x30000000ull, size);
	return 0;
}

int uv_fdt_reserve_mem(unsigned long *fdt, unsigned int npages, unsigned int page_size, u64 *rsv_addr)
{
	unsigned long *rw_fdt;
	u64 rma_top, addr;
	int r, i, n_regions;
	size_t size, fdt_size;

	r = fdt_check_header(fdt);
	if (r < 0)
		return -EINVAL;

	fdt_size = fdt_totalsize(fdt);

#ifdef DEBUG
	uv_fdt_print(fdt);
#endif

	r = uv_get_rma(fdt, &rma_top);
	if (r)
		return r;

	size = npages * page_size;

	/*
	 *  Starting from the top of the RMA, adjust the address until
	 *  there are no overlaps with reserved memory regions.
	 */
	addr = rma_top - size;
	n_regions = fdt_num_mem_rsv(fdt);

	for (i = n_regions - 1; i >= 0; i--) {
		u64 raddr, rsize;

		r = fdt_get_mem_rsv(fdt, i, &raddr, &rsize);
		if(r)
			return -EINVAL;

		if ((addr + size > raddr) && (addr < raddr + rsize)) {
			/* overlap, start over */
			addr = raddr - size;
			i = n_regions;
		}
	}

	/*
	 * For our version of the device-tree (0x10), libdft requires
	 * us to call fdt_open_into before trying a read-write
	 * operation (fdt_add_mem_rsv function below).
	 */
	rw_fdt = kmalloc(fdt_size, GFP_KERNEL);
	if (!rw_fdt)
		return -ENOMEM;

	r = fdt_open_into(fdt, rw_fdt, fdt_size);
	if (r)
		goto out_free;

	r = fdt_add_mem_rsv(rw_fdt, addr, size);
	if (r)
		goto out_free;

	fdt_pack(rw_fdt);

	r = fdt_move(rw_fdt, fdt, fdt_size);
	if (r)
		goto out_free;

#ifdef DEBUG
	uv_fdt_print(fdt);
#endif

	*rsv_addr = addr;

out_free:
	kfree(rw_fdt);
	if (r)
		printk(KERN_INFO "%s failed to reserve %d pages ret=%d\n", __func__, npages, r);
	return r;
}
EXPORT_SYMBOL_GPL(uv_fdt_reserve_mem);
