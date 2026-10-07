/* Constant-time check shim (ctgrind technique).
 *
 * Marks secret bytes as "undefined" for Valgrind's memcheck. memcheck then
 * reports any conditional branch or memory address computed from them --
 * exactly the secret-dependent behaviour constant-time code must not have.
 * Outputs are marked defined again before anything inspects them.
 *
 * Built only for the Linux CI job that runs it (needs valgrind/memcheck.h).
 *
 * Copyright (c) 2026, Matt Doughty
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <valgrind/memcheck.h>

void ct_poison (void *p, size_t n)   { VALGRIND_MAKE_MEM_UNDEFINED (p, n); }
void ct_unpoison (void *p, size_t n) { VALGRIND_MAKE_MEM_DEFINED (p, n); }

/* Distinct, observable callees keep the conditional branch present at -O2.
 * noipa also prevents interprocedural specialization or tail-call merging.
 */
static volatile unsigned int ct_control_sink;

__attribute__((noipa))
static void ct_control_one (void) { ct_control_sink = 1; }

__attribute__((noipa))
static void ct_control_zero (void) { ct_control_sink = 0; }

__attribute__((noipa))
void ct_negative_branch (const unsigned char *secret)
{
    if (*secret)
        ct_control_one ();
    else
        ct_control_zero ();
}

void ct_negative_control (void)
{
    unsigned char secret = 1;
    ct_poison (&secret, sizeof secret);
    ct_negative_branch (&secret);
    ct_unpoison (&secret, sizeof secret);
}
