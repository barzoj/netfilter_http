#include "nf_http_hooks.h"
#include "nf_http_analyzer.h"
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>



/* Linux 4.7.2
 * typedef unsigned int nf_hookfn(void *priv,
 *                              struct sk_buff *skb,
 *                              const struct nf_hook_state *state);
 *
 *
 *
 */

/*
* @brief outgoing packet hook function implementation
*
*/
unsigned int nf_http_outgoing_hook( void *priv, struct sk_buff *skb, const struct nf_hook_state *state )
{

    struct iphdr *iph;
    struct tcphdr *tcph;
    u16 sport, dport;
    u32 saddr, daddr;
    unsigned char *data;
    unsigned char *tail;
    unsigned char *it;

    printk(KERN_DEBUG "%s called.\n", __func__ );

    //skip empty packet
    if ( skb == NULL )
    {
        printk(KERN_DEBUG "%s: network packet is empty\n", __func__);
        return NF_ACCEPT;
    }

    iph = ip_hdr( skb );

    //skip non-tc packet
    if ( iph->protocol != IPPROTO_TCP )
    {
        printk(KERN_DEBUG "%s: skip not TCP packet\n", __func__);
        return NF_ACCEPT;
    }
    tcph = tcp_hdr( skb );

    saddr = ntohl( iph->saddr );
    daddr = ntohl( iph->daddr );
    sport = ntohs( tcph->source );
    dport = ntohs( tcph->dest );

    //get pointer to the payload
    data = ( unsigned char * )( ( unsigned char * )tcph + ( tcph->doff * 4 ) );
    tail = skb_tail_pointer( skb );

    if ( nf_http_analyzer_entry( data, tail ) < UINT_MAX )
    {
        printk( KERN_NOTICE "%s: drop http package: %pI4h:%d -> %pI4h:%d\n \n", __func__, &saddr, sport, &daddr, dport );
        printk( KERN_NOTICE "print_tcp: data:\n" );
            for (it = data; it != tail; ++it) {
                char c = *(char *)it;

                if (c == '\0' || c == '\n')
                    break;

                printk(KERN_NOTICE "%c", c);
            }
            printk("\n\n");

        return NF_DROP;
    }
    return NF_ACCEPT;
}

