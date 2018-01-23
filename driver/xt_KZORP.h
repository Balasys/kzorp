#ifndef _XT_KZORP_H_target
#define _XT_KZORP_H_target

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
/*
* KZORP target makes the necessary decision by your policy settings performs
* redirection, DAC decisions, and forwards services.
*/
struct xt_kzorp_target_info {
	u_int32_t mark_mask; /* same as in xt_tproxy_target_info */
	u_int32_t mark_value; /* same as in xt_tproxy_target_info */
	u_int32_t flags; /*  for future expansion; must be set to 0! */
};

#endif /* _XT_KZORP_H_target */
