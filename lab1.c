#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfho;

/* Hook function to be called by netfilter */
unsigned int hook_func_outgoing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;

    /* Check if packet is TCP */
    if(skb->protocol != htons(ETH_P_IP))
        return NF_ACCEPT;
    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);

        /* Check if it's an outbound SYN packet */
        if (tcph->syn == 1 && tcph->ack == 0) {
            /* TODO 1: Display source IP address and port */
            printk("Outgoing TCP SYN packet from %pI4:%d\n", &iph->saddr, ntohs(tcph->source));
        }
    }

    return NF_ACCEPT;
}

/* Module initialization */
static int __init init_main(void) {
    nfho.hook = hook_func_outgoing;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);
    return 0;
}

/* Module cleanup */
static void __exit exit_main(void) {
    nf_unregister_hook(&nfho);
}

module_init(init_main);
module_exit(exit_main);
