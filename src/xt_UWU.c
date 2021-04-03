/**
 * xt_uwu - uwu the application data.
 * Copyright (C) 2021 Ben Cartwright-Cox <ben@benjojo.co.uk>
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

#include "xt_UWU.h"

#include <linux/module.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ben Cartwright-Cox <ben@benjojo.co.uk>");
MODULE_DESCRIPTION("Xtables: uwu application data");
MODULE_ALIAS("ipt_UWU");

static unsigned int skb_uwu(struct sk_buff *skb, unsigned int offset)
{
	unsigned int headlen = skb_headlen(skb);
	struct sk_buff *frag_iter;

	// In order to preserve protocols like IRC, we must prevent the command word (like PRIVMSG)
	// from being uwu'd (pwivmsg)
	int firstIsAllCaps = 0;
	unsigned int oldOffset = offset;
	unsigned int oldHeadlen = headlen;
	unsigned int letterOffset = 0;

	if (headlen > offset) {
		headlen -= offset;
		while (headlen-- > 0) {
			offset++;
			if (skb->data[offset] >= 'A' && skb->data[offset] <= 'Z') {
				firstIsAllCaps = 1;
				goto zoop;
			}
			if (skb->data[offset] == ' ' || skb->data[offset] == "\t" || 
				skb->data[offset] == "\r" || skb->data[offset] == "\n" ) {
				letterOffset = offset;
				break;
			}
			firstIsAllCaps = 0;
			break;
			zoop: ;
		}
	}

	offset = oldOffset;
	headlen = oldHeadlen;

	if (headlen > offset) {
		headlen -= offset;
		if (firstIsAllCaps) {
			offset = letterOffset;
		}

		while (headlen-- > 0) {
			offset++;
            switch (skb->data[offset]) 
            {
            case 'l':
                skb->data[offset] = 'w';
                break;
            case 'r':
                skb->data[offset] = 'w';
                break;
            case 'L':
                skb->data[offset] = 'W';
                break;
            case 'R':
                skb->data[offset] = 'W';
                break;
            default:
                break;
            }
			// skb->data[offset++] ^= key[key_off++];
		}
		offset = 0;
	} else {
		offset -= headlen;
	}
	skb_walk_frags(skb, frag_iter) {
		if (frag_iter->len > offset) {
			skb_uwu(frag_iter, offset);
			offset = 0;
		} else {
			offset -= frag_iter->len;
		}
	}

	return 0;
}

static unsigned int uwu_tg(struct sk_buff *skb,
		const struct xt_action_param *par)
{
	const struct xt_uwu_info *uwu_info = par->targinfo;
	struct iphdr *iph, _iph;
	unsigned int doff;
	struct sk_buff *last_skb;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph) {
			printk(KERN_ALERT "!iph");
		goto err;
	}

	if (ip_is_fragment(iph)) {
			printk(KERN_ALERT "ip_is_fragment");
		goto err;
	}
	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph, _tcph;

		tcph = skb_header_pointer(skb, par->thoff, sizeof(_tcph),
				&_tcph);
		if (!tcph) {
			printk(KERN_ALERT "tcph");
			goto err;
		}
		doff = tcph->doff * 4;
	} else if (iph->protocol == IPPROTO_UDP) {
		doff = sizeof(struct udphdr);
	} else {
		goto out;
	}
	doff += par->thoff;
	if (skb->len < doff) {
			printk(KERN_ALERT "skb->len < doff");
		goto err;
	}

	if (skb_cow_data(skb, 0, &last_skb) < 0) {
			printk(KERN_ALERT "skb_cow_data");
		goto err;
	}
	skb_uwu(skb, doff);

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph;
		int skfail = skb_ensure_writable(skb, par->thoff + sizeof(*tcph));
		if (skfail < 0) {
			printk(KERN_ALERT "skb_ensure_writable %d", skfail);
			goto err;
		}
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

		if (skb_ensure_writable(skb, doff)) {
			printk(KERN_ALERT "skb_ensure_writable 2");
			goto err;
		}
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
	printk(KERN_ALERT "owo no");
	return NF_DROP;
}

static int uwu_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_uwu_info *uwu_info = par->targinfo;
	return 0;
}

static struct xt_target uwu_tg_reg __read_mostly = {
	.name		= "UWU",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.target		= uwu_tg,
	.targetsize	= sizeof(struct xt_uwu_info),
	.checkentry	= uwu_tg_check,
	.me		= THIS_MODULE
};

static int __init uwu_tg_init(void)
{
	return xt_register_target(&uwu_tg_reg);
}

static void __exit uwu_tg_exit(void)
{
	xt_unregister_target(&uwu_tg_reg);
}

module_init(uwu_tg_init);
module_exit(uwu_tg_exit);
