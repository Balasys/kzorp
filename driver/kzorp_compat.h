#ifndef _KZORP_COMPAT_H
#define _KZORP_COMPAT_H

#include <net/netfilter/nf_conntrack_zones.h>

/* 
 * Copyright (C) 2006-2012, BalaBit IT Ltd.
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


#ifdef NF_CT_DEFAULT_ZONE
#define nf_ct_zone_id(ct) nf_ct_zone((ct))
#else
#define NF_CT_DEFAULT_ZONE NF_CT_DEFAULT_ZONE_ID
#define nf_ct_zone_id(ct) nf_ct_zone((ct))->id
#endif

#ifdef inet_twsk_for_each
#define kz_inet_twsk_deschedule(tw) inet_twsk_deschedule((tw), &tcp_death_row)
#else
#define kz_inet_twsk_deschedule inet_twsk_deschedule
#endif

#ifdef WITH_KZ_TPROXY_CORE_H
	#include "kz_tproxy_core.h"
#else
	#include <net/udp.h>
	#include <net/netfilter/nf_tproxy_core.h>
#endif

#endif /* _KZORP_COMPAT_H */
