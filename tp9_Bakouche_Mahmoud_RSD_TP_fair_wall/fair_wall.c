#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>

MODULE_LICENSE("GPL");

#define IP_A        in_aton("192.168.56.10")//machine a
#define IP_B        in_aton("192.168.56.11") //machine b
#define IP_BLOCKED  in_aton("103.224.182.245") //le site que en va bloque

static struct nf_hook_ops hook_in;
static struct nf_hook_ops hook_out;

static unsigned int fw_in(void *priv,
                          struct sk_buff *skb,
                          const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct icmphdr *icmp_header;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);

        if (ip_header->saddr == IP_B &&
            ip_header->daddr == IP_A &&
            ntohs(tcp_header->dest) == 23) {
            printk(KERN_INFO "[FW] DROP B -> A telnet\n");
            return NF_DROP;
        }
    }

    if (ip_header->protocol == IPPROTO_ICMP) {
        icmp_header = icmp_hdr(skb);

        if (ip_header->saddr == IP_B &&
            ip_header->daddr == IP_A &&
            icmp_header->type == ICMP_ECHO) {
            printk(KERN_INFO "[FW] DROP B -> A ping\n");
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

static unsigned int fw_out(void *priv,
                           struct sk_buff *skb,
                           const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);

        if (ip_header->saddr == IP_A &&
            ip_header->daddr == IP_B &&
            ntohs(tcp_header->dest) == 23) {
            printk(KERN_INFO "[FW] DROP A -> B telnet\n");
            return NF_DROP;
        }

        if (ip_header->daddr == IP_BLOCKED &&
            ntohs(tcp_header->dest) == 80) {
            printk(KERN_INFO "[FW] DROP A -> blocked web HTTP\n");
            return NF_DROP;
        }

        if (ip_header->daddr == IP_BLOCKED &&
            ntohs(tcp_header->dest) == 443) {
            printk(KERN_INFO "[FW] DROP A -> blocked web HTTPS\n");
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

static int __init firewall_init(void)
{
    printk(KERN_INFO "[FW] Firewall module loaded\n");

    hook_in.hook = fw_in;
    hook_in.hooknum = NF_INET_LOCAL_IN;
    hook_in.pf = PF_INET;
    hook_in.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook_in);

    hook_out.hook = fw_out;
    hook_out.hooknum = NF_INET_LOCAL_OUT;
    hook_out.pf = PF_INET;
    hook_out.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook_out);

    return 0;
}

static void __exit firewall_exit(void)
{
    nf_unregister_net_hook(&init_net, &hook_in);
    nf_unregister_net_hook(&init_net, &hook_out);
    printk(KERN_INFO "[FW] Firewall module removed\n");
}

module_init(firewall_init);
module_exit(firewall_exit);