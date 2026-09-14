/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "eth.h"

struct zcrx_redirect_key {
	__u32 ingress_ifindex;
	__u8 destination_mac[ETH_ALEN];
	__u16 pad;
};

struct zcrx_redirect_value {
	__u32 netkit_ifindex;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct zcrx_redirect_key);
	__type(value, struct zcrx_redirect_value);
	__uint(max_entries, 4096);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_zcrx __section_maps_btf;

static __always_inline int
zcrx_redirect(struct __ctx_buff *ctx)
{
	struct zcrx_redirect_key key = {
		.ingress_ifindex = ctx_get_ifindex(ctx),
	};
	struct zcrx_redirect_value *target;

	if (eth_load_daddr(ctx, key.destination_mac, 0) < 0)
		return CTX_ACT_OK;

	target = map_lookup_elem(&cilium_zcrx, &key);
	if (!target)
		return CTX_ACT_OK;

	return ctx_redirect_peer(ctx, target->netkit_ifindex, 0);
}
