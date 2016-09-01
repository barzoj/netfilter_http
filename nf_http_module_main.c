#include <linux/module.h>
#include <linux/kernel.h>
#include "nf_http_hooks.h"

static struct nf_hook_ops nfho = {
    .hook       = nf_http_outgoing_hook,
    .hooknum    = NF_INET_LOCAL_OUT,
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static int __init nf_http_module_init(void)
{
    printk(KERN_NOTICE "%s: init nf_http_module", __func__);
    nf_register_hook(&nfho);

    return 0;
}

static void __exit nf_http_module_exit(void)
{
    printk(KERN_NOTICE "%s: destroy nf_http_module", __func__);
    nf_unregister_hook(&nfho); 
}

module_init(nf_http_module_init);
module_exit(nf_http_module_exit);
MODULE_LICENSE("GPL");
