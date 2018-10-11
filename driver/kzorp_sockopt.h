/*
 * KZorp getsockopt() interface
 *
 * Copyright (C) 2006-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _KZORP_SOCKOPT_H
#define _KZORP_SOCKOPT_H

#include "kzorp_netlink.h"

#define SO_KZORP_RESULT 1678333

struct kz_lookup_result {
	u_int64_t cookie;
	char czone_name[KZ_ATTR_NAME_MAX_LENGTH + 1];
	char szone_name[KZ_ATTR_NAME_MAX_LENGTH + 1];
	char dispatcher_name[KZ_ATTR_NAME_MAX_LENGTH + 1];
	char service_name[KZ_ATTR_NAME_MAX_LENGTH + 1];
	u_int32_t rule_id;
};

#endif
