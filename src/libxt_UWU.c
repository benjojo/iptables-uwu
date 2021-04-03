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

#include "xt_UWU.h"

#include <xtables.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define s struct xt_uwu_info
static const struct xt_option_entry uwu_opts[] = {
	XTOPT_TABLEEND,
};
#undef s


static void uwu_help(void)
{
	printf(
"uwu target options:\n"
"none\n"
	);
}


static void uwu_parse(struct xt_option_call *cb)
{
	struct xt_uwu_info *xor = cb->data;
	int len, i;

	xtables_option_parse(cb);
}

static void uwu_check(struct xt_fcheck_call *cb)
{

}

static void uwu_print(const void *ip, const struct xt_entry_target *target,
		int numeric)
{
	const struct xt_uwu_info *xor = (void *)target->data;
		printf(" nya~ ");
}

static void uwu_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_uwu_info *xor = (void *)target->data;
}

static struct xtables_target uwu_tg_reg = {
	.version	= XTABLES_VERSION,
	.name		= "UWU",
	.family		= PF_INET,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct xt_uwu_info)),
	.userspacesize	= sizeof(struct xt_uwu_info),
	.help		= uwu_help,
	.print		= uwu_print,
	.save		= uwu_save,
	.x6_parse	= uwu_parse,
	.x6_fcheck	= uwu_check,
	.x6_options	= uwu_opts,
};

void _init(void)
{
	xtables_register_target(&uwu_tg_reg);
}
