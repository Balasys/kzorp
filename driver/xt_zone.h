#ifndef _XT_ZONE_H
#define _XT_ZONE_H

/* 
 * Copyright (C) 2006-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
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
/* flags */
enum {
	IPT_ZONE_SRC		= 1 << 0,
	IPT_ZONE_CHILDREN 	= 1 << 1,
	IPT_ZONE_UMBRELLA	= 1 << 2,
	IPT_ZONE_NOCOUNT	= 1 << 3,
};

#define IPT_ZONE_NAME_LENGTH 126
#define IPT_ZONE_NAME_COUNT 32

struct xt_zone_info {
	u_int8_t flags;
	unsigned char name[IPT_ZONE_NAME_LENGTH + 1];
};

struct xt_zone_info_v1 {
	u_int8_t flags;
	u_int8_t count;
	unsigned char names[IPT_ZONE_NAME_COUNT][IPT_ZONE_NAME_LENGTH + 1];
};

struct xt_zone_info_v2 {
	u_int8_t flags;
	u_int8_t count;
	unsigned char names[IPT_ZONE_NAME_COUNT][IPT_ZONE_NAME_LENGTH + 1];
};

struct ipt_zone_info_v2 {
	u_int8_t flags;
	u_int8_t count;
	unsigned char names[IPT_ZONE_NAME_COUNT][IPT_ZONE_NAME_LENGTH + 1];
};

#endif
