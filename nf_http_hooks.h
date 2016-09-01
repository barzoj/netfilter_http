#ifndef NF_HTTP_HOOKS_H_
#define NF_HTTP_HOOKS_H_

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/socket.h>

/*
* @brief outgoing hook function
*/
unsigned int nf_http_outgoing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif
