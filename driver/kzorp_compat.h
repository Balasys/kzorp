#ifndef _KZORP_COMPAT_H
#define _KZORP_COMPAT_H

#include <compat/compat.h>

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

#ifdef KZ_COMP_DOES_NOT_HAVE_TIMER_SETUP

typedef unsigned long kz_timer_arg;

#define kz_from_timer(var, callback_timer, timer_fieldname) \
	(void *)callback_timer;

#define kz_timer_setup(timer, userdata, callback) \
	do { \
		init_timer(&timer); \
		timer.data = (unsigned long)userdata; \
		timer.function = callback; \
	} while (0)

#else

typedef struct timer_list * kz_timer_arg;

#define kz_from_timer(var, callback_timer, timer_fieldname) \
	from_timer(var, callback_timer, timer_fieldname)

#define kz_timer_setup(timer, userdata, callback) \
	timer_setup(&timer, callback, 0)

#endif

#ifdef KZ_COMP_INET_LOOKUP_DOES_NOT_HAVE_SDIF

#define kz_inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif, sdif) \
	inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif)

#define kz_inet6_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif, sdif) \
	inet6_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif)

#define kz___inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif, sdif) \
	__inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif)

#else

#define kz_inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif, sdif) \
	inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif, sdif)

#define kz_inet6_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif, sdif) \
	inet6_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif, sdif)

#define kz___inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif, sdif) \
	__inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif, sdif)

#endif

#endif /* _KZORP_COMPAT_H */
