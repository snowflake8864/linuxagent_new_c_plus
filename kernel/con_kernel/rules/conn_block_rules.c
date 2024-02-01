#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
 #include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "utils/utils.h"
#include "iptree/ipv4_rules.h"
#include "conn_block_rules.h"

struct proc_dir_entry *proc_osec_conn = NULL;
static struct ipv4_rules block_saddr_rt;

int conn_block_init(struct proc_dir_entry *proc_parent)
{
    int retv = 0;
    if((proc_osec_conn = proc_mkdir("osec_conn", proc_parent)) == NULL)
    {   
        printk(KERN_ERR "conn_block: creating proc_fs directory failed.\n");
        return -1;
    }   

    ipv4_rules_init(&block_saddr_rt, "block_saddr_rt", proc_osec_conn);
    return retv;
}

void conn_block_exit(struct proc_dir_entry *proc_parent)
{

    ipv4_rules_purge(&block_saddr_rt);
    remove_proc_entry("osec_conn", proc_parent);
}

bool conn_block_check(__u32 ip)
{
    return  ipv4_rules_check(&block_saddr_rt, ip, NULL);
}

int add_conn_block_rules(__u32 ip)
{
    return ipv4_rules_add_single(&block_saddr_rt, ip);
}
