#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x1e94b2a0, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x85df9b6c, __VMLINUX_SYMBOL_STR(strsep) },
	{ 0x1e6d26a8, __VMLINUX_SYMBOL_STR(strstr) },
	{ 0x61651be, __VMLINUX_SYMBOL_STR(strcat) },
	{ 0x7378123e, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x3d1f7a21, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xda22cdde, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x4f68e5c9, __VMLINUX_SYMBOL_STR(do_gettimeofday) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0xa9aab72c, __VMLINUX_SYMBOL_STR(pv_cpu_ops) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x4c4fef19, __VMLINUX_SYMBOL_STR(kernel_stack) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "A13A4266B772B92A730CDAA");
