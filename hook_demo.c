/********************************************************************

 File name : hook_demo.c

 Description :
----------------------------------------------
 v0.1, 2015-03-14, Wang Zili, creat file
********************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "nf_sockopte.h"

MODULE_LICENSE("Dual BSD/GPL");
#define NF_SUCCESS 0
#define NF_FAILURE 1
band_status b_status;

#define IS_BANDPORT_TCP(status) \
	(status.band_port.port != 0 &&status.band_port.protocol == IPPROTO_TCP)

#define IS_BANDPORT_UDP(status) \
	(status.band_port.port != 0 &&status.band_port.protocol == IPPROTO_UDP)

#define IS_BANDPING(status) (status.band_ping)
#define IS_BANDIP(status) (status.band_ip)

/* nf sock选项扩展操作 */
static int nf_sockopt_set(struct sock *sock,
		int cmd,
		void __user *user,
		unsigned int len)
{
	int ret = 0;
	struct band_status status;

	/* 权限检查 */
	if (!capable(CAP_NET_ADMIN))
	{
		ret = -EPERM;
		goto ERROR;
	}

	ret = copy_from_user(&status, user, len);
	if (ret != 0)
	{
		ret = -EINVAL;
		goto ERROR;
	}

	switch (cmd)
	{
	case SOE_BANDIP :
		if (IS_BANDIP(status))
		{
			b_status.band_ip = status.band_ip;
		}
		else
		{
			b_status.band_ip = 0;
		}
		break;
	case SOE_BANDPORT :
		if (IS_BANDPORT_TCP(status))
		{
			b_status.band_port.protocol = IPPROTO_TCP;
			b_status.band_port.port = status.band_port.port;
		}
		else if (IS_BANDPORT_UDP(status))
		{
			b_status.band_port.protocol = IPPROTO_UDP;
			b_status.band_port.port = status.band_port.port;
		}
		else
		{
			b_status.band_port.protocol = 0;
			b_status.band_port.port = 0;
		}
		break;
	case SOE_BANDPING :
		if (IS_BANDPING(status))
		{
			b_status.band_ping = 1;
		}
		else
		{
			b_status.band_ping = 0;
		}
		break;
	default :
		ret = -EINVAL;
		break;
	}
ERROR:
	return -EINVAL;
}

static int nf_sockopte_get(struct sock *sock,
		int cmd,
		void __user *user,
		unsigned int len)
{
	int ret = 0;

	if (!capable(CAP_NET_ADMIN))
	{
		ret = -EPERM;
		goto ERROR;
	}

	switch (cmd)
	{
	case SOE_BANDIP :
	case SOE_BANDPORT :
	case SOE_BANDPING :
		ret = copy_to_user(user, &b_status, len);
		if (ret != 0)
		{
			ret = -EINVAL;
			goto ERROR;
		}
		break;
	default :
		ret = -EINVAL;
		break;
	}
ERROR:
	return ret;
}

/* 在LOCAL_OUT上挂接钩子 */
static unsigned int nf_hook_out(unsigned int hooknum,
		struct sk_buff **skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff*))
{
	struct sk_buff *sk = *skb;
	struct iphdr *iph = ip_hdr(sk);

	if (IS_BANDIP(b_status))
	{
		if (b_status.band_ip == iph->daddr)
		{
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

/* 在LOCAL_IN挂接钩子 */
static unsigned int nf_hook_in(unsigned int hooknum,
		struct sk_buff **skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff*))
{
	struct sk_buff *sk = *skb;
	struct iphdr *iph = ip_hdr(sk);
	unsigned int src_ip = iph->saddr;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	switch (iph->protocol)
	{
	case IPPROTO_TCP :
		if (IS_BANDPORT_TCP(b_status))
		{
			tcph = tcp_hdr(sk);
			if (tcph->dest == b_status.band_port.port)
			{
				return NF_DROP;
			}
		}
		break;
	case IPPROTO_UDP :
		if (IS_BANDPORT_UDP(b_status))
		{
			udph = udp_hdr(sk);
			if (udph->dest == b_status.band_port.port)
			{
				return NF_DROP;
			}
		}
		break;
	case IPPROTO_ICMP :
		if (IS_BANDPING(b_status))
		{
			printk(KERN_ALERT "DROP ICMP packet from %d.%d.%d.%d\n",
				(src_ip&0xff000000)>>24,
				(src_ip&0x00ff0000)>>16,
				(src_ip&0x0000ff00)>>8,
				(src_ip&0x000000ff)>>0);
			return NF_DROP;
		}
	default :
		break;
	}
	return NF_ACCEPT;
}

/* 初始化nfin钩子 */
static struct nf_hook_ops nfin =
{
	.hook = nf_hook_in,
	.hooknum = NF_INET_LOCAL_IN,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

/* 初始化nfout钩子 */
static struct nf_hook_ops nfout =
{
	.hook = nf_hook_out,
	.hooknum = NF_INET_LOCAL_OUT,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

/* 初始化nf套接字选项 */
static struct nf_sockopt_ops nfsockopt =
{
	.pf = PF_INET,
	.set_optmin = SOE_BANDIP,
	.set_optmax = SOE_BANDIP + 2,
	.set = nf_sockopt_set,
	.get_optmin = SOE_BANDIP,
	.get_optmax = SOE_BANDIP + 2,
	.get = nf_sockopte_get,
};

/* 初始化模块 */
static __init int init()
{
	nf_register_hook(&nfin);
	nf_register_hook(&nfout);
	nf_register_hook(&nfsockopt);
	printk(KERN_ALERT "netfilter demo init successfully\n");
	return NF_SUCCESS;
}

/* 清理模块 */
static void __exit exit()
{
	nf_unregister_hook(&nfin);
	nf_unregister_hook(&nfout);
	nf_unregister_hook(&nfsockopt);
	printk(KERN_ALERT "netfilter demo exit successfully\n");
}

module_init(init);
module_exit(exit);

MODULE_AUTHOR("Wang Zili");
//MODELE_DESCRIPTION("netfilter demo");
MODULE_VERSION("1.0.0");
MODULE_ALIAS("demo");
