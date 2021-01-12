#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Junho, Lee <tot0roprog@gmail.com>");
MODULE_DESCRIPTION("An assignment #3 of system programming in KOREA University");
MODULE_VERSION("NEW");

/* #define PROC_DIRNAME "myproc" */
/* #define PROC_FILENAME "hw2" */
/* #define PORT 33333 */

#define AS_DIR "group999"
#define AS_LIST "show"
#define AS_ADD "add"
#define AS_DEL "del"

struct Chain {
	unsigned int port;
	unsigned char rule; // In-bound, Out-bound, Forward, Proxy
};
static struct Chain chain[999] = {0};
static unsigned int chain_top = 0;
/* module_param(chain, int*, 0660); */
/* module_param(chain_top, int, 0660); */

static struct proc_dir_entry *as_dir, *as_list, *as_add, *as_del;

static int as_open(struct inode *inode, struct file *file)
{
	char const * const str = file->f_path.dentry->d_name.name;
	printk(KERN_INFO "proc file open: %s.\n", str);
	return 0;
}

//unsigned int server_port[5]={33333,4444,5555,6666,7777};

#define PROXY_IP "131.1.1.1"
#define SERVER_IP "192.168.56.101"
#define BUFSIZE 1024


static ssize_t as_read_chain(struct file *file, char __user *ubuf,
				size_t size, loff_t *ppos)
{
	int len = 0;
	char buf[BUFSIZE] = {0};
	char *err_msg = "";
	int i;

	if (*ppos > 0 || size < BUFSIZE) {
		return 0;
	}

	for (i = 0; i < chain_top; i++) {
		len += sprintf(buf, "%s%3d(%c): %5d\n", buf, i, chain[i].rule, chain[i].port);
	}

	if (copy_to_user(ubuf, buf, len)) {
		err_msg = "fail to copy to user";
		goto err;
	}
	*ppos = len;

	return len;
err:
	printk(KERN_INFO "as_read_chain: %s.\n", err_msg);
	return -EFAULT;
}


static ssize_t as_write_add(struct file *file, const char __user *ubuf,
					size_t size, loff_t *ppos)
{
	int len;
	char buf[BUFSIZE];
	char *err_msg = "";
	unsigned int port;
	char rule;

	if (*ppos > 0 || size > BUFSIZE) {
		err_msg = "text size is too big";
		goto err;
	}

	if (copy_from_user(buf, ubuf, size)) {
		err_msg = "fail to copy from user";
		goto err;
	}

	sscanf(buf, " %c %d", &rule, &port);
	len = strlen(buf);

	if (port > 65535) {
		err_msg = "A port number must be less than 65536";
		goto err;
	}

	chain[chain_top].rule = rule;
	chain[chain_top].port = port;
	chain_top++;

	return len;

err:
	printk(KERN_INFO "as_write_add: %s.\n", err_msg);
	return -EFAULT;
}

static ssize_t as_write_del(struct file *file, const char __user *ubuf,
					size_t size, loff_t *ppos)
{
	int len;
	char buf[BUFSIZE];
	char *err_msg = "";
	unsigned int index;
	int i;

	if (*ppos > 0 || size > BUFSIZE) {
		err_msg = "text size is too big";
		goto err;
	}

	if (copy_from_user(buf, ubuf, size)) {
		err_msg = "fail to copy from user";
		goto err;
	}

	sscanf(buf, "%d", &index);
	len = strlen(buf);

	if (index >= chain_top) {
		err_msg = "The index does not exist";
		goto err;
	}

	for (i = index; i < chain_top - 1; i++) {
		chain[i] = chain[i + 1];
	}
	chain_top--;

	return len;

err:
	printk(KERN_INFO "as_write_del: %s.\n", err_msg);
	return -EFAULT;
}

static const struct file_operations show_fops = {
	.owner = THIS_MODULE,
	.open = &as_open,
	.read = &as_read_chain,
};

static const struct file_operations add_fops = {
	.owner = THIS_MODULE,
	.open = &as_open,
	.write = &as_write_add,
};

static const struct file_operations del_fops = {
	.owner = THIS_MODULE,
	.open = &as_open,
	.write = &as_write_del,
};

unsigned int as_inet_addr(char *str)
{
	unsigned char arr[4];
	sscanf(str, "%d.%d.%d.%d", &arr[0], &arr[1], &arr[2], &arr[3]);

	return *(unsigned int *)arr;
}

char *as_addr_inet(unsigned int addr, char str[])
{
	char add[16];
	unsigned char a = ((unsigned char *)&addr)[0];
	unsigned char b = ((unsigned char *)&addr)[1];
	unsigned char c = ((unsigned char *)&addr)[2];
	unsigned char d = ((unsigned char *)&addr)[3];
	sprintf(add, "%u.%u.%u.%u", a, b, c, d);
	sprintf(str, "%s", add);
	return str;
}

static unsigned int pre_my_hook_fn(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *th;
	unsigned int sport, dport;
	char saddr[16] = "dummy", daddr[16] = "dummy";
	int i;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	th = tcp_hdr(skb);
	sport = ntohs(th->source);
	dport = ntohs(th->dest);
	as_addr_inet(iph->saddr, saddr);
	as_addr_inet(iph->daddr, daddr);
	//snprintf(saddr,16,"%pI4",&iph->saddr);
	//snprintf(daddr,16,"%pI4",&iph->daddr);

	if (iph->saddr != as_inet_addr(SERVER_IP))
		return NF_ACCEPT;

	for (i = 0; i < chain_top; i++) {
		if ('I' == chain[i].rule && sport == chain[i].port) {
			printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", "DROP(INBOUND)",
		                          iph->protocol, sport, dport, as_addr_inet(iph->saddr, saddr), daddr,
						  th->syn, th->fin, th->ack, th->rst);
			return NF_DROP;
			// th->rst = 1L;
			// return NF_ACCEPT;
		} else if ('P' == chain[i].rule && sport == chain[i].port) {
			iph->daddr = as_inet_addr(PROXY_IP);
			th->dest = htons(sport);
			printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", "PROXY(INBOUND)",
		                          iph->protocol, sport, th->dest, as_addr_inet(iph->saddr, saddr), as_addr_inet(iph->daddr, daddr),
					  th->syn, th->fin, th->ack, th->rst);
			return NF_ACCEPT;
		}
	}

	printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", "INBOUND",
		                          iph->protocol, sport, dport, as_addr_inet(iph->saddr, saddr), daddr,
						  th->syn, th->fin, th->ack, th->rst);

	return NF_ACCEPT;
}


static unsigned int post_my_hook_fn(void *priv,
			struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *th;
	unsigned int sport, dport;
	char saddr[16] = "dummy", daddr[16] = "dummy";
	int i;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	th = tcp_hdr(skb);
	sport = ntohs(th->source);
	dport = ntohs(th->dest);
	as_addr_inet(iph->saddr, saddr);
	as_addr_inet(iph->daddr, daddr);
	//snprintf(saddr,16,"%pI4",&iph->saddr);
	//snprintf(daddr,16,"%pI4",&iph->daddr);

	if (iph->daddr != as_inet_addr(SERVER_IP) && iph->daddr != as_inet_addr(PROXY_IP))
		return NF_ACCEPT;

	for (i = 0; i < chain_top; i++) {
		if ('O' == chain[i].rule && dport == chain[i].port) {
			printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", "DROP(OUTBOUND)",
		                          iph->protocol, sport, dport, as_addr_inet(iph->saddr, saddr), daddr,
						  th->syn, th->fin, th->ack, th->rst);
			return NF_DROP;
		}
	}

	printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", "OUTBOUND",
		                          iph->protocol, sport, dport, as_addr_inet(iph->saddr, saddr), daddr,
						  th->syn, th->fin, th->ack, th->rst);

	return NF_ACCEPT;
}

static unsigned int forward_my_hook_fn(void *priv,
			struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *th;
	unsigned int sport, dport;
	char saddr[16] = "dummy", daddr[16] = "dummy";
	int i;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	// if (iph->protocol != IPPROTO_TCP)
	//	return NF_ACCEPT;

	th = tcp_hdr(skb);
	sport = ntohs(th->source);
	dport = ntohs(th->dest);
	as_addr_inet(iph->saddr, saddr);
	as_addr_inet(iph->daddr, daddr);
	//snprintf(saddr,16,"%pI4",&iph->saddr);
	//snprintf(daddr,16,"%pI4",&iph->daddr);

	// if (iph->daddr != as_inet_addr(PROXY_IP))
	//	return NF_ACCEPT;

	for (i = 0; i < chain_top; i++) {
		if ('F' == chain[i].rule && dport == chain[i].port) {
			printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", "DROP(FORWARD)",
		                          iph->protocol, sport, dport, as_addr_inet(iph->saddr, saddr), daddr,
						  th->syn, th->fin, th->ack, th->rst);
			return NF_DROP;
		}
	}

	printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", "FORWARD",
		                          iph->protocol, sport, dport, as_addr_inet(iph->saddr, saddr), daddr,
						  th->syn, th->fin, th->ack, th->rst);

	return NF_ACCEPT;
}

static struct nf_hook_ops pre_my_nf_ops={
	.hook = pre_my_hook_fn,
	.hooknum = NF_INET_PRE_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops post_my_nf_ops={
	.hook = post_my_hook_fn,
	.hooknum = NF_INET_POST_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops forward_my_nf_ops={
	.hook = forward_my_hook_fn,
	.hooknum = NF_INET_FORWARD,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};


static int __init as_init(void)
{
	int res = 0;

	chain_top = 0;

	as_dir = proc_mkdir(AS_DIR, NULL);
	if (as_dir == NULL) {
		res = -ENOMEM;
		goto err_mk_dir;
	}

	as_list = proc_create(AS_LIST, 0755, as_dir, &show_fops);
	if (as_list == NULL) {
		res = -ENOMEM;
		goto err_mk_list;
	}

	as_add = proc_create(AS_ADD, 0755, as_dir, &add_fops);
	if (as_add == NULL) {
		res = -ENOMEM;
		goto err_mk_add;
	}

	as_del = proc_create(AS_DEL, 0755, as_dir, &del_fops);
	if (as_del == NULL) {
		res = -ENOMEM;
		goto err_mk_del;
	}

	printk(KERN_INFO "assign module opened.\n");

	nf_register_hook(&pre_my_nf_ops);
	nf_register_hook(&post_my_nf_ops);
	nf_register_hook(&forward_my_nf_ops);
	//nf_register_net_hook(&init_net, &pre_my_nf_ops);
	//nf_register_net_hook(&init_net, &post_my_nf_ops);
	printk(KERN_ALERT"nf hook registered\n");

	return 0;

err_mk_del:
err_mk_add:
err_mk_list:
	proc_remove(as_dir);
err_mk_dir:
	return res;
}

static void __exit as_exit(void)
{
	proc_remove(as_dir);

	printk(KERN_INFO "assign module closed.\n");

	nf_unregister_hook(&pre_my_nf_ops);
	nf_unregister_hook(&post_my_nf_ops);
	nf_unregister_hook(&forward_my_nf_ops);
	//nf_unregister_net_hook(&init_net, &pre_my_nf_ops);
	//nf_unregister_net_hook(&init_net, &post_my_nf_ops);
	printk(KERN_ALERT"nf hook unregistered\n");

	return;
}

module_init(as_init);
module_exit(as_exit);

