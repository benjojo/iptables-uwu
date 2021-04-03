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

#include <xtables.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

enum {
	O_XOR_KEY = 0,
	O_XOR_HEX_KEY,
	F_XOR_KEY     = 1 << O_XOR_KEY,
	F_XOR_HEX_KEY = 1 << O_XOR_HEX_KEY,
	F_XOR_OP_ANY  = F_XOR_KEY | F_XOR_HEX_KEY,
};

#define s struct xt_xor_info
static const struct xt_option_entry XOR_opts[] = {
	{.name = "xor-key", .id = O_XOR_KEY, .type = XTTYPE_STRING,
	 .min = 1, .max = sizeof(((s *)NULL)->key), .excl = F_XOR_HEX_KEY},
	{.name = "xor-hex-key", .id = O_XOR_HEX_KEY, .type = XTTYPE_STRING,
	 .excl = F_XOR_KEY},
	XTOPT_TABLEEND,
};
#undef s

static void XOR_help(void)
{
	printf(
"XOR target options:\n"
"--xor-key key        specify the xor key\n"
"--xor-hex-key key    specify the xor key in hex\n"
	);
}

static int hex2bin(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		abort();
}

static void XOR_parse(struct xt_option_call *cb)
{
	struct xt_xor_info *xor = cb->data;
	int len, i;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_XOR_KEY:
		strncpy((char *)xor->key, cb->arg, sizeof(xor->key));
		xor->key_len = strlen(cb->arg);
		break;
	case O_XOR_HEX_KEY:
		len = strlen(cb->arg);
		if (len == 0) {
			xtables_error(PARAMETER_PROBLEM,
					"KEY must not be empty");
		}
		if (len > sizeof(xor->key) * 2)
			xtables_error(PARAMETER_PROBLEM, "KEY is too long");
		if (len % 2 != 0) {
			xtables_error(PARAMETER_PROBLEM,
					"Odd number of hex digits");
		}
		len /= 2;
		for (i = 0; i < len; i++) {
			if (!isxdigit(cb->arg[i * 2]) ||
			    !isxdigit(cb->arg[i * 2 + 1])) {
				xtables_error(PARAMETER_PROBLEM,
						"Invalid hex char");
			}
			xor->key[i] = (hex2bin(cb->arg[i * 2]) << 4) |
				hex2bin(cb->arg[i * 2 + 1]);
		}
		xor->key_len = len;
		break;
	}
}

static void XOR_check(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_XOR_OP_ANY))
		xtables_error(PARAMETER_PROBLEM,
				"XOR target: You must specify `--xor-key' or "
				"`--xor-hex-key'");
}

static bool is_hex_key(const __u8 *key, __u8 key_len)
{
	 int i;

	 for (i = 0; i < key_len; i++) {
		 if (!isprint(key[i]))
			return true;
	 }

	 return false;
}

static void print_key(const __u8 *key, __u8 key_len)
{
	int i;

	putchar('\"');
	for (i = 0; i < key_len; i++) {
		if (key[i] == '\\' || key[i] == '\"')
			printf("\\%c", key[i]);
		else
			putchar(key[i]);
	}
	putchar('\"');
}

static void print_hex_key(const __u8 *key, __u8 key_len)
{
	int i;

	putchar('\"');
	for (i = 0; i < key_len; i++)
		printf("%02x", key[i]);
	putchar('\"');
}

static void XOR_print(const void *ip, const struct xt_entry_target *target,
		int numeric)
{
	const struct xt_xor_info *xor = (void *)target->data;

	if (is_hex_key(xor->key, xor->key_len)) {
		printf(" xor-hex-key: ");
		print_hex_key(xor->key, xor->key_len);
	} else {
		printf(" xor-key: ");
		print_key(xor->key, xor->key_len);
	}
}

static void XOR_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_xor_info *xor = (void *)target->data;

	if (is_hex_key(xor->key, xor->key_len)) {
		printf(" --xor-hex-key ");
		print_hex_key(xor->key, xor->key_len);
	} else {
		printf(" --xor-key ");
		print_key(xor->key, xor->key_len);
	}
}

static struct xtables_target xor_tg_reg = {
	.version	= XTABLES_VERSION,
	.name		= "XOR",
	.family		= PF_INET,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct xt_xor_info)),
	.userspacesize	= sizeof(struct xt_xor_info),
	.help		= XOR_help,
	.print		= XOR_print,
	.save		= XOR_save,
	.x6_parse	= XOR_parse,
	.x6_fcheck	= XOR_check,
	.x6_options	= XOR_opts,
};

void _init(void)
{
	xtables_register_target(&xor_tg_reg);
}
