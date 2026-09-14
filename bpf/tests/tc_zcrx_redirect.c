// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>

#include "common.h"
#include "pktgen.h"

#define TEST_INGRESS_IFINDEX 1
#define TEST_NETKIT_IFINDEX 42

static volatile __u32 redirected_ifindex;

static int
mock_ctx_redirect_peer(const struct __ctx_buff *ctx __maybe_unused,
		       int ifindex, __u32 flags __maybe_unused)
{
	redirected_ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#define ctx_redirect_peer mock_ctx_redirect_peer
#include "lib/zcrx.h"

static __always_inline int build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;
	struct ethhdr *l2;

	pktgen__init(&builder, ctx);
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	memcpy(l2->h_source, (__u8 *)mac_one, ETH_ALEN);
	memcpy(l2->h_dest, (__u8 *)mac_two, ETH_ALEN);
	l2->h_proto = bpf_htons(ETH_P_IPV6);

	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "no_entry")
int zcrx_redirect_no_entry_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "no_entry")
int zcrx_redirect_no_entry_setup(struct __ctx_buff *ctx)
{
	redirected_ifindex = 0;
	return zcrx_redirect(ctx);
}

CHECK("tc", "no_entry")
int zcrx_redirect_no_entry_check(const struct __ctx_buff *ctx)
{
	__u32 *status = ctx_data(ctx);

	test_init();
	assert((void *)(status + 1) <= ctx_data_end(ctx));
	assert(*status == CTX_ACT_OK);
	assert(redirected_ifindex == 0);
	test_finish();
}

PKTGEN("tc", "matching_entry")
int zcrx_redirect_matching_entry_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "matching_entry")
int zcrx_redirect_matching_entry_setup(struct __ctx_buff *ctx)
{
	struct zcrx_redirect_key key = {
		.ingress_ifindex = TEST_INGRESS_IFINDEX,
	};
	struct zcrx_redirect_value value = {
		.netkit_ifindex = TEST_NETKIT_IFINDEX,
	};

	memcpy(key.destination_mac, (__u8 *)mac_two, ETH_ALEN);
	redirected_ifindex = 0;
	map_update_elem(&cilium_zcrx, &key, &value, BPF_ANY);
	return zcrx_redirect(ctx);
}

CHECK("tc", "matching_entry")
int zcrx_redirect_matching_entry_check(const struct __ctx_buff *ctx)
{
	struct zcrx_redirect_key key = {
		.ingress_ifindex = TEST_INGRESS_IFINDEX,
	};
	__u32 *status = ctx_data(ctx);

	test_init();
	memcpy(key.destination_mac, (__u8 *)mac_two, ETH_ALEN);
	map_delete_elem(&cilium_zcrx, &key);
	assert((void *)(status + 1) <= ctx_data_end(ctx));
	assert(*status == CTX_ACT_REDIRECT);
	assert(redirected_ifindex == TEST_NETKIT_IFINDEX);
	test_finish();
}
