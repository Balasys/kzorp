#ifndef _KZORP_INTERNAL_H
#define _KZORP_INTERNAL_H

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
 * Contains some definitions common to all kzorp compilation unit.
 */

//         DIM_NAME        NL_ATTR_NAME TYPE                  NL_TYPE     LOOKUP_TYPE

#define KZORP_DIM_LIST(ACTION, _) \
  ACTION ( reqid,          REQID,         u_int32_t,            value,         u_int32_t            )_ \
  ACTION ( ifname,         IFACE,         ifname_t,             ifname,        ifname_t             )_ \
  ACTION ( ifgroup,        IFGROUP,       u_int32_t,            value,         u_int32_t            )_ \
  ACTION ( proto,          PROTO,         u_int8_t,             value,         u_int8_t             )_ \
  ACTION ( proto_type,     PROTO_TYPE,    u_int32_t,            value,         u_int32_t            )_ \
  ACTION ( proto_subtype,  PROTO_SUBTYPE, u_int32_t,            value,         u_int32_t            )_ \
  ACTION ( src_port,       SRC_PORT,      struct kz_port_range, portrange,     struct kz_port_range )_ \
  ACTION ( dst_port,       DST_PORT,      struct kz_port_range, portrange,     struct kz_port_range )_ \
  ACTION ( src_in_subnet,  SRC_IP,        struct kz_in_subnet,  in_subnet,     struct kz_in_subnet  )_ \
  ACTION ( src_in6_subnet, SRC_IP6,       struct kz_in6_subnet, in6_subnet,    struct kz_in6_subnet )_ \
  ACTION ( src_zone,       SRC_ZONE,      struct kz_zone *,     string,        struct zone_lookup_t )_ \
  ACTION ( dst_in_subnet,  DST_IP,        struct kz_in_subnet,  in_subnet,     struct kz_in_subnet  )_ \
  ACTION ( dst_in6_subnet, DST_IP6,       struct kz_in6_subnet, in6_subnet,    struct kz_in6_subnet )_ \
  ACTION ( dst_ifname,     DST_IFACE,     ifname_t,             ifname,        ifname_t             )_ \
  ACTION ( dst_ifgroup,    DST_IFGROUP,   u_int32_t,            value,         u_int32_t            )_ \
  ACTION ( dst_zone,       DST_ZONE,      struct kz_zone *,     string,        struct zone_lookup_t )

//         NL_MSG_NAME          RECV_FUNC                    DUMP_FUNC
#define KZORP_MSG_LIST(ACTION, _) \
  ACTION ( GET_VERSION,            get_version,                NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( START,                  start,                      NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( COMMIT,                 commit,                     NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( FLUSH_ZONE,             flush_z,                    NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( ADD_ZONE,               add_zone,                   NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( GET_ZONE,               get_zone,                   zones,             KZNL_OP   )_ \
  ACTION ( FLUSH_SERVICE,          flush_s,                    NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( ADD_SERVICE,            add_service,                NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( ADD_SERVICE_NAT_SRC,    add_service_nat_src,        NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( ADD_SERVICE_NAT_DST,    add_service_nat_dst,        NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( GET_SERVICE,            get_service,                services,          KZNL_OP   )_ \
  ACTION ( FLUSH_DISPATCHER,       flush_d,                    NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( ADD_DISPATCHER,         add_dispatcher,             NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( GET_DISPATCHER,         get_dispatcher,             dispatchers,       KZNL_OP   )_ \
  ACTION ( QUERY,                  query,                      NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( ADD_RULE,               add_n_dimension_rule,       NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( ADD_RULE_ENTRY,         add_n_dimension_rule_entry, NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( ADD_BIND,               add_bind,                   NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( GET_BIND,               NO_RECV_FUNC,               binds,             KZNL_OP   )_ \
  ACTION ( FLUSH_BIND,             flush_b,                    NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( QUERY_REPLY,            NO_RECV_FUNC,               NO_DUMP_FUNC,      KZNL_NOOP )_ \
  ACTION ( GET_VERSION_REPLY,      NO_RECV_FUNC,               NO_DUMP_FUNC,      KZNL_NOOP )_ \
  ACTION ( ADD_ZONE_SUBNET,        add_zone_subnet,            NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( LOOKUP_ZONE,            lookup_zone,                NO_DUMP_FUNC,      KZNL_OP   )_ \
  ACTION ( DELETE_ZONE,            delete_zone,                NO_DUMP_FUNC,      KZNL_OP   )_ \

#define KZORP_COMMA_SEPARATOR ,

#endif /* _KZORP_INTERNAL_H */
