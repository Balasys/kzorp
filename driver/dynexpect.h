#ifndef _NF_CONNTRACK_DYNEXPECT_H
#define _NF_CONNTRACK_DYNEXPECT_H

#define SO_DYNEXPECT_MAP 11281
#define SO_DYNEXPECT_EXPECT 11282
#define SO_DYNEXPECT_DESTROY 11283
#define SO_DYNEXPECT_MARK 11284

struct nf_ct_dynexpect_map
{
	u_int32_t mapping_id;
	__be32 orig_ip;
	__be32 new_ip;
	__be16 orig_port;
	u_int16_t n_ports;
	__be16 new_port;
	u_int8_t proto;
	u_int8_t __res1;
	u_int32_t n_active;
} __attribute__((packed));

struct nf_ct_dynexpect_expect
{
	u_int32_t mapping_id;
	__be32 peer_ip;
	__be16 peer_port;
} __attribute__((packed));

struct nf_ct_dynexpect_destroy
{
	u_int32_t mapping_id;
} __attribute__((packed));

struct nf_ct_dynexpect_mark
{
	u_int32_t mapping_id;
	u_int32_t mark;
} __attribute__((packed));

/* nat helper private information */
struct nf_ct_dyn_expect
{
	u_int32_t mapping_id;
} __attribute__((packed));

#endif /* _NF_CONNTRACK_DYNEXPECT_H */
