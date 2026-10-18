# Reads `objdump -d --no-show-raw-insn` output (GNU objdump or LLVM's)
# and prints, for each return instruction of the function named FN, the
# registers that hold zero on every path that reaches it from the
# function's last call or branch. One line per return:
#
#   ret: rax rcx rdx r8 ... xmm0 ...
#
# Used by check-hardening.sh to confirm that GCC's zero_call_used_regs
# ("all") clears every call-used register before a hardened entry point
# returns, including registers only its callees used.
#
# How a return's list is built (a span is the run of instructions that
# ends at the return):
#   * the span starts empty after each call, branch or return, and at each
#     instruction some branch of the function targets: on a path that
#     jumps there, nothing before it ran. The targets are collected first,
#     from the direct branches' operands (GNU's "10 <fn+0x10>" and LLVM's
#     "0x10 <fn+0x10>"); a target labelled with another symbol (a cold
#     part, another function) is not in this function. A function with an
#     indirect jump (jmp *%rax, br x1), whose targets are unknown, has an
#     empty list at every return;
#   * a register enters the span when an instruction zeroes all of it: an
#     xor, pxor or eor of the register with itself, a mov, movi or fmov of
#     zero into it, vzeroall, or a copy of a register already in the span.
#     On x86-64 a 32-bit write zero-extends (xor %eax,%eax clears rax) but
#     an 8- or 16-bit one does not (xorw %ax,%ax leaves bits 16-63). On
#     AArch64 a write to w<n> zero-extends to x<n>, and every write to a
#     SIMD&FP register by its scalar (b/h/s/d/q) or vector (v<n>.<T>) name
#     clears the rest of the 128-bit register (movi d0,#0 and fmov s0,wzr
#     both zero v0); a write of one element (v0.s[1], ins) does not;
#   * a register leaves the span when a later instruction writes it (any
#     view of it): the destination of an x86 AT&T instruction (its last
#     operand) or of an AArch64 one (its first; both for ldp), the base
#     register of a pre- or post-indexed access, and the implicit
#     destinations of pop, leave, mul, div and the like. A store writes no
#     register but its base on writeback; a compare writes none. An
#     instruction whose destinations cannot be told (cpuid, syscall, an
#     undecoded byte, a mnemonic with no operands outside a short list of
#     known forms) empties the span. So an epilogue that restores only
#     callee-saved registers, sp, fp or lr keeps the call-used registers
#     zeroed before it, and a load into a zeroed register removes it.
#
# Not seen: a jump into the function from elsewhere. A cold part
# (<fn>.cold) that jumps back into its function is a separate symbol, and
# a function whose cold part rejoins it is analysed as if the cold path
# did not exist. The second report, below, lists the jumps that leave a
# function; check-hardening.sh fails a cold part that has any, and checks
# the returns in it.
#
# Relocation records (objdump -r) are read, never taken for instructions:
#   GNU, ELF:    "\t\t\t5: R_X86_64_PLT32\tsym-0x4"
#   GNU, COFF:   "\t\t\t5: IMAGE_REL_AMD64_REL32\tsym"
#   LLVM, Mach-O "\t\t0000000000000008:  ARM64_RELOC_BRANCH26\t_sym"
# A record follows the instruction whose field it patches (its address is
# the field's, inside that instruction) and names the instruction's real
# target, which in an object file the instruction shows only as a
# placeholder (a branch to itself or to the next instruction). Its type
# is upper case; a mnemonic never is. On Mach-O an addend comes in an
# ARM64_RELOC_ADDEND record of its own, before the record it applies to.
#
# The architecture is x86-64 when an operand names a register with AT&T's
# %, and AArch64 otherwise. The branch, call and return mnemonics of the
# two do not overlap, so they are told apart whatever the architecture
# (an x86-64 cold part may have no register operand at all).
#
# With -v report=exits the output is instead one line per symbol that a
# jump of FN leaves to, sorted, each once:
#
#   exit: NAME
#
# A jump is any branch that is not a call or a return (call, bl, blr,
# ret and ret x30 are not). It leaves FN when
#   * it is indirect (jmp *%rax, jmp *0x8(%rip), br x1, br x16, braaz x1),
#     with or without a record: its target is not known. NAME is
#     "*indirect*";
#   * a relocation record follows it (the record replaces the
#     placeholder). NAME is the symbol the record names, without its
#     addend. A record that names FN itself keeps its addend as the
#     record shows it, with no bias applied ("fn+0xc", "fn-0x4"; "fn"
#     with none, as COFF's records show it, whose addend is in the
#     instruction): the jump goes to an offset of FN, not to
#     the placeholder the default report takes for its target, so it is
#     listed rather than resolved here. A record that names FN's section
#     symbol (.text.fn, .text$fn) or a Mach-O section-start alias (ltmp0)
#     is listed like any other symbol;
#   * or else its target is labelled with a symbol other than FN or an
#     alias of it at FN's address ("10 <other+0x4>"). NAME is the symbol
#     without its offset.
# FN also leaves, into whatever follows it, when it runs off its end: its
# last instruction, after any trailing padding (nop, nopw, nopl,
# xchg %ax,%ax), is not a return, an unconditional jump (direct or
# indirect), a trap (ud2, int3, hlt, brk, udf) or a call (a call to a
# routine that does not return ends a cold part). NAME is then
# "*falls-through* INSN", INSN that instruction with its blanks squeezed
# ("*falls-through* mov x0, #0x2a"), or "(nothing but padding)" or "(no
# instruction)".
# When FN's own symbol has the Mach-O underscore, NAME is without a
# leading underscore. A function with no jump out prints nothing; one not
# in the input prints "none".
#
# Registers are normalised so that the x86-64 and AArch64 spellings of one
# register compare equal: al/ah/ax/eax/rax -> rax, r8b/r8w/r8d -> r8,
# xmm/ymm/zmm -> xmm, w/x -> x, and the AArch64 SIMD&FP register views
# v/q/d/s/h/b -> v.
#
# When FN is not in the input, or has no return, the output is "none".
#
# Usage: awk -v fn=blake2b__hashing__final -f zeroed-at-return.awk dis.txt
#        awk -v fn=blake2b__hashing__final -v report=exits \
#          -f zeroed-at-return.awk dis.txt
#        (fn matches the symbol with or without a leading underscore)
#
# Copyright (c) 2026, Matt Doughty
# SPDX-License-Identifier: BSD-3-Clause

function norm(r) {
  r = tolower(r)
  gsub(/[%{} \t]/, "", r)
  sub(/\[[0-9]+\]$/, "", r)                 # AArch64 element: v0[1] (LLVM)
  sub(/\..*$/, "", r)                       # AArch64 arrangement: v0.16b
  if (r ~ /^[er]?(ax|bx|cx|dx|si|di|bp|sp)$/) { sub(/^[er]/, "", r); return "r" r }
  if (r ~ /^[abcd][lh]$/) { return "r" substr(r, 1, 1) "x" }
  if (r ~ /^(sil|dil|bpl|spl)$/) { return "r" substr(r, 1, 2) }
  if (r ~ /^r[0-9]+[dwbl]?$/) { sub(/[dwbl]$/, "", r); return r }
  if (r ~ /^[xyz]mm[0-9]+$/) { sub(/^[xyz]/, "x", r); return r }
  if (r ~ /^[wx][0-9]+$/) { sub(/^[wx]/, "x", r); return r }
  if (r ~ /^[vqdshb][0-9]+$/) { sub(/^[vqdshb]/, "v", r); return r }
  if (r == "lr") return "x30"
  if (r == "fp") return "x29"
  if (r == "wsp") return "rsp"
  if (r == "wzr") return "xzr"
  return r
}

# Whether operand o names a register (not memory, an immediate or a label).
function is_reg(o) {
  if (arch == "x86") return o ~ /^%[a-z0-9]+(\([0-9]\))?(\{[^}]*\})*$/
  return o ~ /^(x[0-9]+|w[0-9]+|[vqdshb][0-9]+|z[0-9]+|p[0-9]+|sp|wsp|xzr|wzr|lr|fp)(\.[0-9]*[bhsdq])?(\[[0-9]+\])?$/
}

# Whether a write to register operand o sets the whole register (so a
# write of zero zeroes it): not an 8- or 16-bit x86 view, not one element
# of an AArch64 vector.
function is_whole(o,    r) {
  r = tolower(o)
  gsub(/[%{} \t]/, "", r)
  if (arch == "x86")
    return !(r ~ /^([abcd][xlh]|si|di|bp|sp|sil|dil|bpl|spl)$/ || r ~ /^r[0-9]+[wbl]$/)
  return r !~ /\[[0-9]+\]$/
}

function is_zero_imm(s) {
  gsub(/[ \t]/, "", s)
  return s ~ /^[#$]?(0x)?0+(\.0+)?$/ || s == "xzr" || s == "wzr"
}

# Splits operand string s at the commas outside (), [] and {} into ops[1..];
# returns the count.
function split_ops(s,    n, i, c, depth, cur) {
  n = 0; depth = 0; cur = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "(" || c == "[" || c == "{") depth++
    else if (c == ")" || c == "]" || c == "}") depth--
    if (c == "," && depth == 0) { ops[++n] = cur; cur = ""; continue }
    cur = cur c
  }
  if (cur ~ /[^ \t]/) ops[++n] = cur
  for (i = 1; i <= n; i++) gsub(/^[ \t]+|[ \t]+$/, "", ops[i])
  return n
}

# Adds the registers written by the register operand or register list o
# to wr[].
function add_written(o,    k, a, i) {
  if (o ~ /^\{/) {                          # AArch64 list: { v0.16b, v1.16b }[1]
    sub(/\}.*$/, "", o); sub(/^\{/, "", o)
    k = split(o, a, ",")
    for (i = 1; i <= k; i++) { gsub(/^[ \t]+|[ \t]+$/, "", a[i]); wr[norm(a[i])] = 1 }
    return
  }
  if (is_reg(o)) wr[norm(o)] = 1
}

# Classifies instruction (base mnemonic m, operands ops[1..n]). Fills wr[]
# with the registers it writes and returns "ok", or returns "zero" with
# zr set to the register it zeroes whole, or returns "unknown".
function classify(m, n,    i, r, same, src) {
  for (r in wr) delete wr[r]
  zr = ""
  if (arch == "x86") {
    # Zeroing idioms.
    if ((m ~ /^v?p?xor(b|w|l|q|ps|pd|d)?$/ || m ~ /^kxor[bwdq]$/) && n >= 2) {
      r = norm(ops[1]); same = is_reg(ops[1])
      for (i = 2; i <= n; i++) if (!is_reg(ops[i]) || norm(ops[i]) != r) same = 0
      if (same) {
        if (is_whole(ops[n])) { zr = r; return "zero" }
        wr[r] = 1; return "ok"
      }
    }
    if (m == "vzeroall") { zr = "*vzeroall"; return "zero" }
    if (m ~ /^mov[lq]?$/ && n == 2 && is_reg(ops[2]) && is_whole(ops[2]) \
        && is_zero_imm(ops[1])) { zr = norm(ops[2]); return "zero" }
    # A copy of a zeroed register.
    if (m ~ /^(mov[lqd]?|v?mov(aps|apd|ups|upd|dqa|dqu)|vmovdq[au](32|64)|v?movq|v?movd)$/ \
        && n == 2 && is_reg(ops[1]) && is_reg(ops[2]) && is_whole(ops[1]) \
        && is_whole(ops[2]) && (norm(ops[1]) in span)) {
      zr = norm(ops[2]); return "zero"
    }
    # String operations write rdi, rsi, rcx and rax implicitly.
    if (string_op) { wr["rax"] = wr["rcx"] = wr["rdi"] = wr["rsi"] = 1; return "ok" }
    if (n == 0) {
      if (m ~ /^(nop[wlq]?|endbr(32|64)|vzeroupper|emms|femms|fninit|finit|lfence|mfence|sfence|pause|int3|ud2|hlt|cld|std|clc|stc|cmc|fld[z1]|fldpi|fldl2[et]|fldlg2|fldln2|wait|fwait)$/)
        return "ok"
      if (m ~ /^leave[lqw]?$/) { wr["rbp"] = wr["rsp"] = 1; return "ok" }
      if (m ~ /^(cltq|cdqe|cwtl|cbtw|cwde|cbw)$/) { wr["rax"] = 1; return "ok" }
      if (m ~ /^(cqto|cqo|cltd|cdq|cwtd|cwd)$/) { wr["rax"] = wr["rdx"] = 1; return "ok" }
      return "unknown"
    }
    if (m ~ /^(cmp[bwlq]?|test[bwlq]?|bt[wlq]?|v?u?comis[sd]|v?ptest|nop[wlq]?|prefetch[a-z0-9]*|clflush[a-z]*)$/)
      return "ok"
    if (m ~ /^push[wlq]?$/) { wr["rsp"] = 1; return "ok" }
    if (m ~ /^pop[wlq]?$/) { wr["rsp"] = 1; add_written(ops[1]); return "ok" }
    if (m ~ /^(i?mul|i?div)[bwlq]?$/ && n == 1) {
      wr["rax"] = wr["rdx"] = 1; return "ok"
    }
    if (m ~ /^(xchg|xadd)[bwlq]?$/) {
      for (i = 1; i <= n; i++) add_written(ops[i])
      return "ok"
    }
    if (m ~ /^cmpxchg[bwlq]?$/) { wr["rax"] = 1; add_written(ops[n]); return "ok" }
    if (m ~ /^cmpxchg(8|16)b$/) { wr["rax"] = wr["rdx"] = 1; return "ok" }
    if (m ~ /^mulx[lq]?$/) { add_written(ops[n]); add_written(ops[n - 1]); return "ok" }
    if (m ~ /^v?pcmp[ei]stri$/) { wr["rcx"] = 1; return "ok" }
    if (m ~ /^v?pcmp[ei]strm$/) { wr["xmm0"] = 1; return "ok" }
    if (m ~ /^(cpuid|rdtscp?|rdpmc|rdmsr|syscall|sysenter|xgetbv|in[bwl]?|xlatb?|int|into|fxrstor(64)?|xrstors?(64)?)$/)
      return "unknown"
    add_written(ops[n])
    return "ok"
  }
  # AArch64.
  if ((m == "mov" || m == "movz" || m == "movi" || m == "fmov") && n == 2 \
      && is_reg(ops[1])) {
    if (is_zero_imm(ops[2])) {
      if (is_whole(ops[1])) { zr = norm(ops[1]); return "zero" }
      wr[norm(ops[1])] = 1; return "ok"
    }
    if (m != "movi" && is_reg(ops[2]) && is_whole(ops[1]) && is_whole(ops[2]) \
        && (norm(ops[2]) in span)) { zr = norm(ops[1]); return "zero" }
  }
  if (m == "eor" && n == 3 && is_reg(ops[1])) {
    r = norm(ops[1])
    if (is_reg(ops[2]) && is_reg(ops[3]) && norm(ops[2]) == r && norm(ops[3]) == r) {
      if (is_whole(ops[1])) { zr = r; return "zero" }
      wr[r] = 1; return "ok"
    }
  }
  if (m == "orr" && n == 3 && is_reg(ops[1]) && is_reg(ops[2]) && is_reg(ops[3]) \
      && norm(ops[2]) == norm(ops[3]) && is_whole(ops[1]) && (norm(ops[2]) in span)) {
    zr = norm(ops[1]); return "zero"
  }
  # The base register of a pre-indexed ([x0, #8]!) or post-indexed
  # ([x0], #8) access is written.
  for (i = 1; i <= n; i++) {
    if (ops[i] ~ /^\[/ && (ops[i] ~ /!$/ || i < n)) {
      r = ops[i]; sub(/^\[[ \t]*/, "", r); sub(/[ \t]*[],].*$/, "", r)
      wr[norm(r)] = 1
    }
  }
  if (n == 0) {
    if (m ~ /^(nop|isb|csdb|sb|ssbb|pssbb|yield|wfe|wfi|sev|sevl|esb|clrex|udf|brk)$/)
      return "ok"
    if (m ~ /^(paci|auti)[ab](sp|z)$/ || m == "xpaclri") { wr["x30"] = 1; return "ok" }
    if (m ~ /^(paci|auti)[ab]1716$/) { wr["x17"] = 1; return "ok" }
    return "unknown"
  }
  if (m ~ /^(cmp|cmn|tst|fcmpe?|ccmp|ccmn|fccmpe?|dsb|dmb|bti|hint|prfu?m|msr|dc|ic|tlbi|brk|udf|hlt)$/)
    return "ok"
  if (m ~ /^(svc|hvc|smc)$/) return "unknown"
  if (m ~ /^(casp?|swp|ld(add|clr|eor|set|smax|smin|umax|umin))(a|al|l)?[bh]?$/) {
    for (i = 1; i <= n; i++) add_written(ops[i])
    return "ok"
  }
  if (m ~ /^stl?xr[bh]?$/ || m ~ /^stl?xp$/) { add_written(ops[1]); return "ok" }
  if (m ~ /^st/) return "ok"
  if (m ~ /^ld[a-z]*p(sw)?$/) { add_written(ops[1]); add_written(ops[2]); return "ok" }
  add_written(ops[1])
  return "ok"
}

function reset_span(    k) { for (k in span) delete span[k] }

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

# A hex address in a canonical form: no 0x, no leading zeros, lower case.
function canon(a) {
  a = tolower(a)
  sub(/^0x/, "", a)
  sub(/^0+/, "", a)
  return a == "" ? "0" : a
}

# Parses instruction text t into mnem (the mnemonic, without prefixes or,
# for AArch64 LLVM, the arrangement suffix: movi.2d -> movi) and ops[1..];
# returns the operand count. Sets string_op for an x86 string operation.
function parse(t,    w, n, i) {
  string_op = 0
  for (;;) {
    w = t; sub(/[ \t].*$/, "", w)
    if (w ~ /^(rep|repz|repe|repnz|repne)$/) string_op = 1
    else if (!(tolower(w) ~ /^(lock|notrack|bnd|data16|data32|addr16|addr32|cs|ds|ss|es|fs|gs|rex(\.[wrxb]+)?|xacquire|xrelease|\{vex3?\}|\{evex\})$/))
      break
    if (t !~ /[ \t]/) break
    sub(/^[^ \t]+[ \t]+/, "", t)
  }
  mnem = tolower(w)
  t = substr(t, length(w) + 1)
  sub(/^[ \t]+/, "", t)
  n = split_ops(t)
  if (mnem ~ /^(ret[lqw]?|nop[wlq]?)$/) string_op = 0
  if (mnem ~ /^(stos|lods|scas|cmps|movs|ins|outs)[bwlq]?$/) {
    string_op = 1
    for (i = 1; i <= n; i++) if (ops[i] ~ /%[xyz]mm/) string_op = 0
  }
  if (mnem !~ /^bc?\./) sub(/\..*$/, "", mnem)
  return n
}

# Whether the target symbol s (from "<s+0x10>") is this function.
function own_symbol(s,    k, a, i) {
  sub(/\+.*$/, "", s)
  sub(/^_/, "", s)
  k = split(fn_names, a, " ")
  for (i = 1; i <= k; i++) {
    sub(/^_/, "", a[i])
    if (a[i] == s) return 1
  }
  return 0
}

# Whether symbol s, named by a relocation record (its addend removed), is
# FN itself. An alias at FN's address is not: a section-start alias plus
# an addend (ltmp0+0x1900) can name another function.
function is_fn(s,    f) {
  f = fn
  sub(/^_/, "", s)
  sub(/^_/, "", f)
  return s == f
}

# Symbol s without its offset or addend ("+0x10", "-0x4") and, when FN's
# own symbol has the Mach-O underscore, without a leading underscore.
function bare(s) {
  sub(/[+-]0x[0-9a-fA-F]+$/, "", s)
  if (prefixed) sub(/^_/, "", s)
  return s
}

# Whether the instruction just parsed (mnem, ops[1..n]) is alignment
# padding: a nop, in any of x86-64's multi-byte forms (nopw, nopl, with
# their cs and data16 prefixes) or as xchg %ax,%ax (66 90).
function is_padding(n) {
  if (mnem ~ /^nop[wlq]?$/) return 1
  return mnem ~ /^xchgw?$/ && n == 2 && tolower(ops[1]) == "%ax" \
      && tolower(ops[2]) == "%ax"
}

# Whether mnemonic m ends every path through it: a return, an
# unconditional jump (direct or indirect), a trap, or a call (a call to a
# routine that does not return is how GCC ends a cold part).
function is_terminator(m) {
  return m ~ /^ret(l|q|w|aa|ab)?$/ || m ~ /^(l?jmp[lqw]?|b|br|bra[ab]z?)$/ \
      || m ~ /^(ud2|int3|hlt|brk|udf)$/ || is_call(m)
}

# Adds "*falls-through* INSN" to exits[] if the buffered function's last
# instruction, after any trailing padding, does not end every path.
function collect_fall_through(    i, n, t) {
  for (i = ninsn; i >= 1; i--) {
    n = parse(insn_text[i])
    if (!is_padding(n)) break
  }
  if (i < 1) t = "(nothing but padding)"
  else if (is_terminator(mnem)) return
  else t = insn_text[i]
  gsub(/[ \t]+/, " ", t)
  exits["*falls-through* " t] = 1
}

# Adds to exits[] the symbols the jumps of the buffered function leave to,
# "*indirect*" for an indirect jump, and "*falls-through* INSN" if it
# runs off its end.
function collect_exits(    i, n, k, j, a, last, sym) {
  collect_fall_through()
  for (i = 1; i <= ninsn; i++) {
    n = parse(insn_text[i])
    if (!is_branch(mnem)) continue
    if (is_indirect(n)) { exits["*indirect*"] = 1; continue }
    if (insn_reloc[i] != "") {
      k = split(insn_reloc[i], a, " ")
      for (j = 1; j <= k; j++) {
        sym = a[j]; sub(/[+-]0x[0-9a-fA-F]+$/, "", sym)
        if (is_fn(sym)) {
          sym = a[j]
          if (prefixed) sub(/^_/, "", sym)
          exits[sym] = 1
        } else exits[bare(sym)] = 1
      }
      continue
    }
    last = n > 0 ? ops[n] : ""
    if (last !~ /<[^>]+>/) continue
    sym = last; sub(/^[^<]*</, "", sym); sub(/>.*$/, "", sym)
    if (own_symbol(sym)) continue
    sub(/\+.*$/, "", sym)
    exits[bare(sym)] = 1
  }
}

function print_exits(    k, sorted, n, i, j, t) {
  n = 0
  for (k in exits) { n++; sorted[n] = k }
  for (i = 2; i <= n; i++) {                # insertion sort, for stable output
    t = sorted[i]; j = i - 1
    while (j >= 1 && sorted[j] > t) { sorted[j + 1] = sorted[j]; j-- }
    sorted[j + 1] = t
  }
  for (i = 1; i <= n; i++) print "exit: " sorted[i]
}

# Analyses the buffered function: insn_addr[1..ninsn], insn_text[1..ninsn]
# and the relocation records' symbols, insn_reloc[1..ninsn].
function analyse(    i, n, k, targets, indirect, last, a, sym, kind) {
  arch = "aarch64"
  for (i = 1; i <= ninsn; i++) if (insn_text[i] ~ /%/) { arch = "x86"; break }
  if (report == "exits") { collect_exits(); return }
  indirect = 0
  for (i = 1; i <= ninsn; i++) {
    n = parse(insn_text[i])
    if (!is_branch(mnem)) continue
    if (is_indirect(n)) { indirect = 1; continue }
    last = ops[n]
    a = last; sub(/[ \t].*$/, "", a)
    sym = ""
    if (last ~ /<[^>]+>/) { sym = last; sub(/^[^<]*</, "", sym); sub(/>.*$/, "", sym) }
    if (sym == "" || own_symbol(sym)) targets[canon(a)] = 1
  }
  reset_span()
  for (i = 1; i <= ninsn; i++) {
    if (indirect || (canon(insn_addr[i]) in targets)) reset_span()
    n = parse(insn_text[i])
    if (mnem ~ /^ret(l|q|w|aa|ab)?$/) { emit(); reset_span(); continue }
    if (is_branch(mnem) || is_call(mnem)) { reset_span(); continue }
    kind = classify(mnem, n)
    if (kind == "unknown") { reset_span(); continue }
    for (k in wr) delete span[k]
    if (kind == "zero") {
      if (zr == "*vzeroall") { for (k = 0; k < 16; k++) span["xmm" k] = 1 }
      else span[zr] = 1
    }
  }
}

# Whether mnemonic m is a jump: a branch that is not a call or a return.
# x86-64's and AArch64's do not overlap, so both are matched whatever the
# architecture.
function is_branch(m) {
  return m ~ /^(l?jmp[lqw]?|j[a-z]+|loop[a-z]*|xbegin)$/ \
      || m ~ /^(b|bc?\.[a-z]+|cbn?z|tbn?z|br|bra[ab]z?)$/
}

function is_call(m) {
  return m ~ /^l?call[lqw]?$/ || m ~ /^(bl|blr|blra[ab]z?)$/
}

# Whether the jump just parsed (mnem, ops[1..n]) is indirect: through a
# register or memory (jmp *%rax, jmp *0x8(%rip), br x1, braaz x1), or with
# an operand that is not an address, so its target is not known.
function is_indirect(n,    last, a) {
  last = n > 0 ? ops[n] : ""
  if (mnem ~ /^bra/ || mnem == "br" || last ~ /^\*/ \
      || (arch == "aarch64" && is_reg(last)) || (arch == "x86" && last ~ /%/))
    return 1
  a = last; sub(/[ \t].*$/, "", a)
  return a !~ /^(0x)?[0-9a-fA-F]+$/
}

function finish() {
  if (inside && ninsn > 0) analyse()
  else if (inside && report == "exits")
    exits["*falls-through* (no instruction)"] = 1
  ninsn = 0
}

BEGIN { inside = 0; found_ret = 0; last_addr = ""; insn_since_header = 1; ninsn = 0; group = "" }

{ sub(/\r$/, "") }                           # output with CRLF line ends

# A symbol header: "0000000000000000 <name>:". Several can label one
# address: on Mach-O, LLVM's objdump prints section-start aliases
# (ltmp0, ...) next to the function's own symbol, in either order. Headers
# at the same address with no instruction between them are one place, so
# the function is "inside" if any of them is its name, and a branch target
# labelled with any of them is in the function.
/^[0-9a-fA-F]+ <[^>]+>:[ \t]*$/ {
  addr = $1
  name = $0
  sub(/^[0-9a-fA-F]+ </, "", name); sub(/>:[ \t]*$/, "", name)
  this = (name == fn || name == "_" fn)
  if (this) found_fn = 1
  if (name == "_" fn) prefixed = 1
  if (addr == last_addr && !insn_since_header) {
    now = inside || this
    group = group " " name
  } else {
    now = this
    group = name
  }
  if (inside && !now) finish()
  if (now && !inside) ninsn = 0
  inside = now
  if (inside) fn_names = group
  last_addr = addr
  insn_since_header = 0
  next
}

# A relocation record: its symbol goes with the instruction before it. An
# ARM64_RELOC_ADDEND record (Mach-O) carries the addend of the record
# after it, not a symbol; it is kept with that record's symbol when the
# symbol is FN itself (the exits report lists it with its addend).
/^[ \t]+[0-9a-fA-F]+:[ \t]+(R_|IMAGE_REL_|[A-Z0-9]+_RELOC_)[A-Z0-9_]*([ \t]|$)/ {
  if (inside && ninsn > 0 && NF >= 3) {
    if ($2 ~ /ADDEND/) addend = $3
    else {
      s = $3
      if (addend != "" && is_fn(s)) s = s "+" addend
      insn_reloc[ninsn] = insn_reloc[ninsn] " " s
      addend = ""
    }
  }
  next
}

/^[ \t]+[0-9a-fA-F]+:/ { insn_since_header = 1 }

inside && /^[ \t]+[0-9a-fA-F]+:/ {
  line = $0
  a = line; sub(/^[ \t]+/, "", a); sub(/:.*$/, "", a)
  sub(/^[ \t]+[0-9a-fA-F]+:[ \t]*/, "", line)
  # Trailing comments. AArch64 disassemblers comment with // (GNU) or ;
  # (LLVM). On x86-64 a comment is # after a gap of columns. A # straight
  # after an operand separator is an AArch64 immediate (mov x0, #0), never
  # a comment.
  sub(/[ \t]*(\/\/|;).*$/, "", line)
  sub(/[ \t][ \t]+#.*$/, "", line)
  if (line == "") next
  ninsn++
  insn_addr[ninsn] = a
  insn_text[ninsn] = line
  insn_reloc[ninsn] = ""
  addend = ""
  next
}

END {
  finish()
  if (report == "exits") {
    if (found_fn) print_exits()
    else print "none"
  } else if (!found_ret) print "none"
}
