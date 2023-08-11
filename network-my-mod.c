#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>

#define MAX_IPS 100
#define MAX_IP_STR_LEN 20

static struct nf_hook_ops *nfho = NULL;
static struct proc_dir_entry *ip_rec_proc;
static char IPs[MAX_IPS][MAX_IP_STR_LEN];

int read_proc(struct file *filp, char *buf, size_t count, loff_t *offp)
{
	int bytes_read = 0;
	char (*msg_ptr)[MAX_IP_STR_LEN] = IPs;
	int num_rows = sizeof(IPs)/ sizeof(IPs[0]);
	int i = 0;

	if (*offp >= num_rows){
	 	*offp = 0;	
		return 0;
	}

	msg_ptr += *offp;

	while(i < MAX_IP_STR_LEN &&(*msg_ptr)[i]) {
		put_user((*msg_ptr)[i], buf++);
		i++;
		count--;
		bytes_read++;
	}

	msg_ptr++;
	(*offp)++;

	if (count > 0) {
       	 	put_user('\n', buf++);
        	count--;
        	bytes_read++;
	}

    	return bytes_read;

}

static void ip_to_array(__be32 ip, char array[4]){
	array[0] = (ip >> 24) & 0xFF;
    	array[1] = (ip >> 16) & 0xFF;
    	array[2] = (ip >> 8) & 0xFF;
    	array[3] = ip & 0xFF;
}

static void append_to_string_array(char *ipAddr){
	static int current_size = 0;

	if (current_size >= MAX_IPS){
		memmove(IPs[0], IPs[1], (MAX_IPS - 1) * MAX_IP_STR_LEN);
		current_size--;
	}

	strncpy(IPs[current_size], ipAddr, sizeof(IPs[current_size]));
	IPs[current_size][sizeof(IPs[current_size]) - 1] = '\0';
	current_size++;

}

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	static __be32 prevIP = 0;
	static char ip_addr[MAX_IP_STR_LEN];
	static char ip_array[4];

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (prevIP != iph->saddr){
		ip_to_array(iph->saddr, ip_array);
		snprintf(ip_addr, sizeof(ip_addr), "%d.%d.%d.%d\n", ip_array[3], ip_array[2], ip_array[1], ip_array[0]);
		append_to_string_array(ip_addr);
		printk("ip address %pks\n", IPs);
	}
	prevIP = iph->saddr;
	return NF_ACCEPT;
}

struct file_operations ip_rec_proc_fops = {
	read: read_proc
};


static int __init network_mod_init(void)
{
	printk("Network mod init\n");
	ip_rec_proc = proc_create("ip_records", 0666, NULL, &ip_rec_proc_fops);
	if (ip_rec_proc == NULL)
	{
		return -1;
	}

	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	nfho->hook 	= (nf_hookfn*)hfunc;		/* hook function */
	nfho->hooknum 	= NF_INET_PRE_ROUTING;		/* received packets */
	nfho->pf 	= PF_INET;			/* IPv4 */
	nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */

	nf_register_net_hook(&init_net, nfho);
	return 0;
}

static void __exit network_mod_exit(void)
{
	printk("Network mod exited\n");
	remove_proc_entry("ip_records", NULL);
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(network_mod_init);
module_exit(network_mod_exit);
