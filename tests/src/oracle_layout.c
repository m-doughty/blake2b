/* The sizes of the two C oracles' incremental states, so that Oracles
 * can check that its Ada declarations of them match the vendored headers.
 *
 * Copyright (c) 2026, Matt Doughty
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>

#include "blake2.h"
#include "monocypher.h"

size_t oracles_reference_state_size(void)
{
    return sizeof(blake2b_state);
}

size_t oracles_monocypher_ctx_size(void)
{
    return sizeof(crypto_blake2b_ctx);
}
