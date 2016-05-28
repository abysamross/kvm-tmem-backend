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
	{ 0x3ef6acc2, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xc18bb284, __VMLINUX_SYMBOL_STR(alloc_pages_current) },
	{ 0x3356b90b, __VMLINUX_SYMBOL_STR(cpu_tss) },
	{ 0x8130d5db, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0xeffd4733, __VMLINUX_SYMBOL_STR(kernel_sendmsg) },
	{ 0xda3e43d1, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0x487ff0fe, __VMLINUX_SYMBOL_STR(debugfs_create_dir) },
	{ 0xd6ee688f, __VMLINUX_SYMBOL_STR(vmalloc) },
	{ 0xb5dcab5b, __VMLINUX_SYMBOL_STR(remove_wait_queue) },
	{ 0x2103d28a, __VMLINUX_SYMBOL_STR(sock_release) },
	{ 0x8b900f3b, __VMLINUX_SYMBOL_STR(_raw_read_lock) },
	{ 0x65415e82, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0x999e8297, __VMLINUX_SYMBOL_STR(vfree) },
	{ 0x4629334c, __VMLINUX_SYMBOL_STR(__preempt_count) },
	{ 0x9e88343e, __VMLINUX_SYMBOL_STR(debugfs_remove_recursive) },
	{ 0xcad68c05, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0xece784c2, __VMLINUX_SYMBOL_STR(rb_first) },
	{ 0x47d1e2f8, __VMLINUX_SYMBOL_STR(kvm_tmem_bknd_enabled) },
	{ 0xffd5a395, __VMLINUX_SYMBOL_STR(default_wake_function) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x6798a936, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0xa236cd38, __VMLINUX_SYMBOL_STR(kvm_tmem_dedup_enabled) },
	{ 0xda14c1f8, __VMLINUX_SYMBOL_STR(use_cleancache) },
	{ 0xc6e8769a, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xe15f42bb, __VMLINUX_SYMBOL_STR(_raw_spin_trylock) },
	{ 0x2855c2a4, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xec0229db, __VMLINUX_SYMBOL_STR(debugfs_create_u64) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0x4d9b652b, __VMLINUX_SYMBOL_STR(rb_erase) },
	{ 0xa63b4701, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x668ae44f, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0x143687b2, __VMLINUX_SYMBOL_STR(_raw_write_lock) },
	{ 0xf07a7048, __VMLINUX_SYMBOL_STR(kvm_host_tmem_deregister_ops) },
	{ 0x7fbd10d2, __VMLINUX_SYMBOL_STR(radix_tree_next_chunk) },
	{ 0x952664c5, __VMLINUX_SYMBOL_STR(do_exit) },
	{ 0xe50e115f, __VMLINUX_SYMBOL_STR(kvm_host_tmem_register_ops) },
	{ 0x3c483012, __VMLINUX_SYMBOL_STR(radix_tree_delete) },
	{ 0x65535802, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0x31e0353a, __VMLINUX_SYMBOL_STR(__free_pages) },
	{ 0xd62c833f, __VMLINUX_SYMBOL_STR(schedule_timeout) },
	{ 0x904bf21f, __VMLINUX_SYMBOL_STR(crypto_destroy_tfm) },
	{ 0x69d08d67, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x5a80c8ca, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xd52bf1ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0xa5526619, __VMLINUX_SYMBOL_STR(rb_insert_color) },
	{ 0x780f252d, __VMLINUX_SYMBOL_STR(kmem_cache_create) },
	{ 0xb21b699, __VMLINUX_SYMBOL_STR(kernel_recvmsg) },
	{ 0xb3f7646e, __VMLINUX_SYMBOL_STR(kthread_should_stop) },
	{ 0x34f22f94, __VMLINUX_SYMBOL_STR(prepare_to_wait_event) },
	{ 0x5860aad4, __VMLINUX_SYMBOL_STR(add_wait_queue) },
	{ 0xb6244511, __VMLINUX_SYMBOL_STR(sg_init_one) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x6df1aaf1, __VMLINUX_SYMBOL_STR(kernel_sigaction) },
	{ 0xb4d65e51, __VMLINUX_SYMBOL_STR(sock_create) },
	{ 0xfa66f77c, __VMLINUX_SYMBOL_STR(finish_wait) },
	{ 0x844e3767, __VMLINUX_SYMBOL_STR(radix_tree_lookup) },
	{ 0xca9360b5, __VMLINUX_SYMBOL_STR(rb_next) },
	{ 0xc3754cb1, __VMLINUX_SYMBOL_STR(crypto_alloc_base) },
	{ 0x614bb773, __VMLINUX_SYMBOL_STR(radix_tree_insert) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=kvm";


MODULE_INFO(srcversion, "5352A30F77711A3BB14AA34");
