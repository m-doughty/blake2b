# Reads `objdump -d --no-show-raw-insn` output (GNU objdump or LLVM's)
# and prints, for each return instruction of the function named FN, the
# registers zeroed on the way out: those zeroed after the function's last
# call or branch before that return. One line per return:
#
#   ret: rax rcx rdx r8 ... xmm0 ...
#
# Used by check-hardening.sh to confirm that GCC's zero_call_used_regs
# ("all") clears every call-used register before a hardened entry point
# returns, including registers only its callees used.
#
# Registers are normalised so that the x86-64 and AArch64 spellings of one
# register compare equal: eax/rax -> rax, r8d -> r8, xmm/ymm -> xmm,
# w/x -> x, and the AArch64 vector register views v/q/d/s/h/b -> v.
#
# Usage: awk -v fn=blake2b__hashing__final -f zeroed-at-return.awk dis.txt
#        (fn matches the symbol with or without a leading underscore)
#
# Copyright (c) 2026, Matt Doughty
# SPDX-License-Identifier: BSD-3-Clause

function norm(r) {
  r = tolower(r)
  gsub(/[%{} \t]/, "", r)
  sub(/\..*$/, "", r)                       # AArch64 arrangement: v0.16b
  if (r ~ /^[er]?(ax|bx|cx|dx|si|di|bp|sp)$/) { sub(/^[er]/, "", r); return "r" r }
  if (r ~ /^(al|bl|cl|dl)$/) { sub(/l$/, "x", r); return "r" r }
  if (r ~ /^r[0-9]+[dwb]?$/) { sub(/[dwb]$/, "", r); return r }
  if (r ~ /^[xyz]mm[0-9]+$/) { sub(/^[xyz]/, "x", r); return r }
  if (r ~ /^[wx][0-9]+$/) { sub(/^[wx]/, "x", r); return r }
  if (r ~ /^[vqdshb][0-9]+$/) { sub(/^[vqdshb]/, "v", r); return r }
  return r
}

function is_zero_imm(s) {
  gsub(/[ \t]/, "", s)
  return s ~ /^#?(0x)?0+(\.0+)?$/ || s ~ /^#?0+$/ || s == "xzr" || s == "wzr"
}

# Records the registers zeroed by instruction (mnemonic m, operands ops),
# if it is a zeroing idiom, into the current span.
function note_zeroing(m, ops,    n, a, i, r, same) {
  n = split(ops, a, ",")
  for (i = 1; i <= n; i++) gsub(/^[ \t]+|[ \t]+$/, "", a[i])
  m = tolower(m)
  # x86-64: xor/pxor/xorps/xorpd of a register with itself (2 or 3
  # operand forms), and vzeroall.
  if (m ~ /^v?p?xor(l|q|w|ps|pd)?$/ && n >= 2) {
    r = norm(a[1]); same = 1
    for (i = 2; i <= n; i++) if (norm(a[i]) != r) same = 0
    if (same && r != "") span[r] = 1
    return
  }
  if (m == "vzeroall") { for (i = 0; i < 16; i++) span["xmm" i] = 1; return }
  # AArch64: mov/movi/fmov of zero, and eor of a register with itself.
  if ((m ~ /^movi(\.[0-9a-z]+)?$/ || m == "mov" || m == "fmov" || m == "movz") && n == 2) {
    if (is_zero_imm(a[2])) span[norm(a[1])] = 1
    return
  }
  if (m ~ /^eor(\.[0-9a-z]+)?$/ && n == 3) {
    r = norm(a[1])
    if (norm(a[2]) == r && norm(a[3]) == r) span[r] = 1
    return
  }
}

function emit(    k, list, sorted, n, i, j, t) {
  n = 0
  for (k in span) { n++; sorted[n] = k }
  for (i = 2; i <= n; i++) {                # insertion sort, for stable output
    t = sorted[i]; j = i - 1
    while (j >= 1 && sorted[j] > t) { sorted[j + 1] = sorted[j]; j-- }
    sorted[j + 1] = t
  }
  list = ""
  for (i = 1; i <= n; i++) list = list " " sorted[i]
  print "ret:" list
  found_ret = 1
}

function reset_span(    k) { for (k in span) delete span[k] }

BEGIN { inside = 0; found_ret = 0; last_addr = ""; insn_since_header = 1 }

# A symbol header: "0000000000000000 <name>:". Several can label one
# address: on Mach-O, LLVM's objdump prints section-start aliases
# (ltmp0, ...) next to the function's own symbol, in either order. Headers
# at the same address with no instruction between them are one place, so
# the function is "inside" if any of them is its name.
/^[0-9a-fA-F]+ <[^>]+>:[ \t]*$/ {
  addr = $1
  name = $0
  sub(/^[0-9a-fA-F]+ </, "", name); sub(/>:[ \t]*$/, "", name)
  this = (name == fn || name == "_" fn)
  if (addr == last_addr && !insn_since_header) inside = inside || this
  else inside = this
  last_addr = addr
  insn_since_header = 0
  reset_span()
  next
}

/^[ \t]+[0-9a-fA-F]+:/ { insn_since_header = 1 }

inside && /^[ \t]+[0-9a-fA-F]+:/ {
  line = $0
  sub(/^[ \t]+[0-9a-fA-F]+:[ \t]*/, "", line)
  # Trailing comments. AArch64 disassemblers comment with // (GNU) or ;
  # (LLVM). On x86-64 a comment is # after a gap of columns. A # straight
  # after an operand separator is an AArch64 immediate (mov x0, #0), never
  # a comment.
  sub(/[ \t]*(\/\/|;).*$/, "", line)
  sub(/[ \t][ \t]+#.*$/, "", line)
  if (line == "") next
  m = line; sub(/[ \t].*$/, "", m)
  ops = line; sub(/^[^ \t]+[ \t]*/, "", ops)
  lm = tolower(m)
  if (lm ~ /^ret[lqw]?$/) { emit(); reset_span(); next }
  # Calls and branches end a span: anything zeroed before them may be
  # dirtied again by the callee or on the other path.
  if (lm ~ /^(call[lqw]?|jmp[lqw]?|j[a-z]+|bl|blr|br|b|b\.[a-z]+|cbn?z|tbn?z)$/) {
    reset_span(); next
  }
  note_zeroing(m, ops)
  next
}

END { if (!found_ret) print "none" }
