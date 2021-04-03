/**
 * xt_XOR - XOR the application data.
 * Copyright (C) 2013 Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "xt_XOR.h"

#include <linux/module.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Xtables: XOR the application data");
MODULE_ALIAS("ipt_XOR");

static unsigned int skb_xor(struct sk_buff *skb, unsigned int offset,
		const u8 *key, unsigned int key_len, unsigned int key_off)
{
	unsigned int headlen = skb_headlen(skb);
	struct sk_buff *frag_iter;

	if (headlen > offset) {
		headlen -= offset;
		while (headlen-- > 0) {
			skb->data[offset++] ^= key[key_off++];
			if (key_off == key_len)
				key_off = 0;
		}
		offset = 0;
	} else {
		offset -= headlen;
	}
	skb_walk_frags(skb, frag_iter) {
		if (frag_iter->len > offset) {
			key_off = skb_xor(frag_iter, offset, key, key_len,
					key_off);
			offset = 0;
		} else {
			offset -= frag_iter->len;
		}
	}

	return key_off;
}

static unsigned int xor_tg(struct sk_buff *skb,
		const struct xt_action_param *par)
{
	const struct xt_xor_info *xor_info = par->targinfo;
	struct iphdr *iph, _iph;
	unsigned int doff;
	struct sk_buff *last_skb;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph)
		goto err;
	/**
	 * This check is redundant, since we speficy the dependency on
	 * nf_defrag_ipv4 explicitly in xor_tg_init().
	 */
	if (ip_is_fragment(iph))
		goto err;
	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph, _tcph;

		tcph = skb_header_pointer(skb, par->thoff, sizeof(_tcph),
				&_tcph);
		if (!tcph)
			goto err;
		doff = tcph->doff * 4;
	} else if (iph->protocol == IPPROTO_UDP) {
		doff = sizeof(struct udphdr);
	} else {
		goto out;
	}
	doff += par->thoff;
	if (skb->len < doff)
		goto err;

	if (skb_cow_data(skb, 0, &last_skb) < 0)
		goto err;
	skb_xor(skb, doff, xor_info->key, xor_info->key_len, 0);

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph;

		if (!skb_try_make_writable(skb, par->thoff + sizeof(*tcph)))
			goto err;
		iph = ip_hdr(skb);
		tcph = (struct tcphdr *)(skb->data + par->thoff);
		tcph->check = ~csum_tcpudp_magic(iph->saddr,
				iph->daddr, skb->len - par->thoff,
				IPPROTO_TCP, 0);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = (unsigned char *)tcph - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		struct udphdr *udph;

		if (!skb_try_make_writable(skb, doff))
			goto err;
		iph = ip_hdr(skb);
		udph = (struct udphdr *)(skb->data + par->thoff);
		if (udph->check) {
			udph->check = ~csum_tcpudp_magic(iph->saddr,
					iph->daddr, skb->len - par->thoff,
					IPPROTO_UDP, 0);
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = (unsigned char *)udph - skb->head;
			skb->csum_offset = offsetof(struct udphdr, check);
		}
	}
out:
	return XT_CONTINUE;
err:
	return NF_DROP;
}

static int xor_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_xor_info *xor_info = par->targinfo;

	if (xor_info->key_len <= 0 || xor_info->key_len > sizeof(xor_info->key))
		return -EINVAL;

	return 0;
}

static struct xt_target xor_tg_reg __read_mostly = {
	.name		= "XOR",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.target		= xor_tg,
	.targetsize	= sizeof(struct xt_xor_info),
	.checkentry	= xor_tg_check,
	.me		= THIS_MODULE
};

static int __init xor_tg_init(void)
{
	return xt_register_target(&xor_tg_reg);
}

static void __exit xor_tg_exit(void)
{
	xt_unregister_target(&xor_tg_reg);
}

module_init(xor_tg_init);
module_exit(xor_tg_exit);
