// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include "lib/endian.h"
#include "lib/zcrx.h"

__section_entry
int cil_zcrx_redir(struct __sk_buff *ctx)
{
	return zcrx_redirect(ctx);
}

BPF_LICENSE("Dual BSD/GPL");
