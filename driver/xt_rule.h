#ifndef _XT_RULE_H
#define _XT_RULE_H

/* 
 * Copyright (C) 2014-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

enum {
	IPT_RULE_ID		= 1 << 0,
	IPT_RULE_NOCOUNT	= 1 << 1,
};

struct ipt_rule_info_v0 {
	u_int8_t flags;
	u_int32_t id;
};

#endif
