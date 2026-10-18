#!/usr/bin/env bash
# Tests scripts/zeroed-at-return.awk, the parser check-hardening.sh uses,
# against the disassembly formats CI meets: GNU objdump (Linux, Windows)
# and LLVM objdump (macOS), on x86-64 and AArch64. That includes AArch64
# immediates, which are written "#0" like an x86 comment, and the Mach-O
# section-start aliases (ltmp0) that label a function's first address.
# Then the second report, the jumps that leave a function (a cold part
# that rejoins its function, a tail jump to a helper), from labels and
# from the relocation records objdump -r prints in an object file (LLVM
# Mach-O, GNU ELF and GNU COFF), which the first report must ignore; a
# record that names the function itself, listed with its addend;
# indirect jumps, listed as "*indirect*", but not calls or returns; and
# a function that runs off its end, listed as "*falls-through*" with its
# last instruction, but not one that ends in a return, an unconditional
# jump, a trap or a call, before any nop padding.
#
# Usage: scripts/test-zeroed-at-return.sh

set -euo pipefail
cd "$(dirname "$0")/.."

pass=0
bad=0
# Runs the parser on stdin for function $2; compares with $3.
expect () {
  check "$1" "$3" "$(awk -v fn="$2" -f scripts/zeroed-at-return.awk)"
}

# The same for the second report, the jumps out (report=exits).
expect_exits () {
  check "$1" "$3" \
    "$(awk -v fn="$2" -v report=exits -f scripts/zeroed-at-return.awk)"
}

# Compares the output $3 of test $1 with $2.
check () {
  local label=$1 want=$2 got=$3
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
  else
    echo "FAILED: $label"
    echo "  want: $want"
    echo "  got:  $got"
    bad=$((bad + 1))
  fi
}

expect "x86-64, GNU objdump, with a # comment" probe \
  'ret: r8 rax rdx xmm0 xmm1' <<'EOF'
0000000000000000 <probe>:
   0:	mov    0x0(%rip),%rax        # 7 <probe+0x7>
   7:	call   c <probe+0xc>
   c:	xor    %eax,%eax
   e:	xor    %edx,%edx
  10:	pxor   %xmm0,%xmm0
  14:	pxor   %xmm1,%xmm1
  18:	xor    %r8d,%r8d
  1b:	ret
EOF

expect "x86-64: zeroing before a call doesn't count" probe \
  'ret: rax' <<'EOF'
0000000000000000 <probe>:
   0:	pxor   %xmm0,%xmm0
   4:	call   9 <probe+0x9>
   9:	xor    %eax,%eax
   b:	ret
EOF

expect "x86-64, LLVM objdump, Mach-O underscore" probe \
  'ret: rax rcx xmm2' <<'EOF'
0000000000000000 <_probe>:
       0:	xorl	%eax, %eax
       2:	xorl	%ecx, %ecx
       4:	pxor	%xmm2, %xmm2
       8:	retq
EOF

expect "AArch64, GNU objdump (Linux)" probe \
  'ret: v0 v1 x0 x1' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0                   	// #0
   4:	mov	x1, #0x0                   	// #0
   8:	movi	v0.4s, #0x0
   c:	movi	v1.2d, #0x0
  10:	ret
EOF

expect "AArch64, LLVM objdump, Mach-O, alias before the symbol" probe \
  'ret: v0 v31 x0 x17' <<'EOF'
0000000000000000 <ltmp0>:
0000000000000000 <_probe>:
       0: 	mov	x0, #0
       4: 	mov	x17, #0
       8: 	movi.2d	v0, #0000000000000000
       c: 	movi.16b	v31, #0
      10: 	ret
EOF

expect "AArch64, LLVM objdump, Mach-O, alias after the symbol" probe \
  'ret: v0 x0' <<'EOF'
0000000000000000 <_probe>:
0000000000000000 <ltmp0>:
       0: 	mov	x0, #0
       4: 	movi	d0, #0000000000000000
       8: 	ret
EOF

expect "AArch64: a later alias at another address ends the function" probe \
  'ret: x0' <<'EOF'
0000000000000000 <_probe>:
       0: 	mov	x0, #0
       4: 	ret
0000000000000008 <ltmp1>:
       8: 	mov	x1, #0
       c: 	ret
EOF

expect "AArch64: a call ends the zeroed span" probe \
  'ret: x1' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0
   4:	bl	0 <other>
   8:	mov	x1, #0x0
   c:	ret
EOF

expect "no such function" probe 'none' <<'EOF'
0000000000000000 <other>:
   0:	ret
EOF

# A later write to a zeroed register un-zeroes it.
expect "x86-64: a load into a zeroed register" probe 'ret: rdx' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	xor    %edx,%edx
   4:	mov    (%rdi),%rax
   7:	ret
EOF

expect "x86-64: a write to an 8-bit view (ah) of a zeroed register" probe \
  'ret:' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	mov    $0x1,%ah
   4:	ret
EOF

expect "AArch64: ldr and ldp into zeroed registers" probe 'ret: x2' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0                   	// #0
   4:	mov	x1, #0x0                   	// #0
   8:	mov	x2, #0x0                   	// #0
   c:	mov	x3, #0x0                   	// #0
  10:	ldp	x0, x1, [x2]
  14:	ldr	w3, [x2, #8]
  18:	ret
EOF

expect "AArch64: movk and an element write un-zero" probe 'ret:' <<'EOF'
0000000000000000 <_probe>:
       0: 	mov	x0, #0
       4: 	movi.2d	v0, #0000000000000000
       8: 	movk	x0, #0x1, lsl #16
       c: 	mov.s	v0[1], w1
      10: 	ret
EOF

expect "store writeback writes its base, a plain store nothing" probe \
  'ret: x1' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0                   	// #0
   4:	mov	x1, #0x0                   	// #0
   8:	str	xzr, [x0, #-8]!
   c:	str	x2, [x1]
  10:	ret
EOF

# Width: an 8- or 16-bit x86 clear leaves the upper bits; 32-bit and
# 64-bit clears, and every AArch64 register view but one element, clear
# the whole register.
expect "x86-64: 8- and 16-bit clears don't count" probe \
  'ret: r10 rdx rsi' <<'EOF'
0000000000000000 <probe>:
   0:	xorw   %ax,%ax
   3:	xorb   %cl,%cl
   5:	xor    %r8w,%r8w
   9:	xor    %r9b,%r9b
   c:	xor    %edx,%edx
   e:	xor    %r10d,%r10d
  11:	xorq   %rsi,%rsi
  14:	ret
EOF

expect "x86-64, LLVM: mov of zero counts in 32 bits, not in 16" probe \
  'ret: rax' <<'EOF'
0000000000000000 <_probe>:
       0:	movl	$0, %eax
       5:	movw	$0, %cx
       9:	retq
EOF

expect "AArch64: w, s, d and 64-bit vector writes clear the register" probe \
  'ret: v2 v3 v4 v5 x0 x1' <<'EOF'
0000000000000000 <probe>:
   0:	mov	w0, #0x0                   	// #0
   4:	eor	w1, w1, w1
   8:	fmov	s2, wzr
   c:	movi	d3, #0x0
  10:	fmov	d4, xzr
  14:	movi	v5.8b, #0x0
  18:	mov	v6.s[1], wzr
  1c:	ret
EOF

expect "a copy of a zeroed register is zero" probe \
  'ret: rax rdx' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	mov    %eax,%edx
   4:	movaps %xmm0,%xmm1
   7:	ret
EOF

# Branch targets: a path that jumps past the zeroing skips it.
expect "AArch64, GNU: a branch to the ret skips the zeroing" probe \
  'ret:' <<'EOF'
0000000000000000 <probe>:
   0:	cbz	x1, c <probe+0xc>
   4:	mov	x0, #0x0                   	// #0
   8:	nop
   c:	ret
EOF

expect "AArch64, LLVM: a branch into the zeroing" probe 'ret: x1' <<'EOF'
0000000000000000 <_probe>:
       0: 	tbz	w2, #3, 0x8 <_probe+0x8>
       4: 	mov	x0, #0
       8: 	mov	x1, #0
       c: 	ret
EOF

expect "AArch64, LLVM: a target labelled by the Mach-O alias" probe \
  'ret:' <<'EOF'
0000000000000000 <ltmp0>:
0000000000000000 <_probe>:
       0: 	cbnz	x1, 0x8 <ltmp0+0x8>
       4: 	mov	x0, #0
       8: 	ret
EOF

expect "x86-64: a conditional jump to the ret" probe 'ret:' <<'EOF'
0000000000000000 <probe>:
   0:	test   %edi,%edi
   2:	je     8 <probe+0x8>
   4:	xor    %eax,%eax
   6:	xor    %edx,%edx
   8:	ret
EOF

expect "a branch target before the zeroing doesn't matter" probe \
  'ret: x0 x1' <<'EOF'
0000000000000000 <_probe>:
       0: 	cmp	x1, x0
       4: 	b.hs	0x10 <_probe+0x10>
       8: 	str	xzr, [x0, #-0x8]!
       c: 	b.lo	0x8 <_probe+0x8>
      10: 	ldp	x29, x30, [sp], #0x20
      14: 	mov	x0, #0
      18: 	mov	x1, #0
      1c: 	ret
EOF

expect "a jump to another symbol (a cold part) is not a target here" probe \
  'ret: rax rdx' <<'EOF'
0000000000000000 <probe>:
   0:	test   %edi,%edi
   2:	je     6 <probe.cold+0x6>
   4:	xor    %eax,%eax
   6:	xor    %edx,%edx
   8:	ret
EOF

expect "an indirect jump: any instruction may be a target" probe 'ret:' <<'EOF'
0000000000000000 <probe>:
   0:	jmp    *%rcx
   2:	xor    %eax,%eax
   4:	ret
EOF

# Epilogues: restoring callee-saved registers, sp, fp or lr after the
# zeroing keeps it.
expect "x86-64: pop, add to rsp and leave after the zeroing" probe \
  'ret: rax' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	xor    %ecx,%ecx
   4:	add    $0x8,%rsp
   8:	pop    %rbx
   9:	pop    %rbp
   a:	pop    %rcx
   b:	leave
   c:	ret
EOF

expect "AArch64: ldp of fp and lr, add to sp and autiasp after the zeroing" \
  probe 'ret: v0 x0' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0                   	// #0
   4:	movi	v0.2d, #0x0
   8:	ldp	x29, x30, [sp], #32
   c:	ldr	x19, [sp, #16]
  10:	add	sp, sp, #0x30
  14:	autiasp
  18:	ret
EOF

expect "x86-64, GNU (Linux): endbr64 and the x87 clearing keep the span" \
  probe 'ret: rax xmm0' <<'EOF'
0000000000000000 <probe>:
   0:	endbr64
   4:	xor    %eax,%eax
   6:	fldz
   8:	fstp   %st(0)
   a:	pxor   %xmm0,%xmm0
   e:	ret
EOF

expect "an instruction with unknown destinations empties the span" probe \
  'ret: rdx' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	cpuid
   4:	xor    %edx,%edx
   6:	ret
EOF

expect "x86-64: a string operation writes rax, rcx, rdi and rsi" probe \
  'ret: rdx' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	xor    %ecx,%ecx
   4:	xor    %edx,%edx
   6:	rep stos %rax,%es:(%rdi)
   9:	repz ret
EOF

# Line ends and section headers. objdump's output read from a file
# written on Windows can end its lines with CRLF; GNU objdump on COFF
# (Windows) with -ffunction-sections puts a section header before each
# function.
crlf () { awk '{ printf "%s\r\n", $0 }'; }

expect "x86-64, GNU objdump, CRLF line ends" probe \
  'ret: rax rdx xmm0' < <(crlf <<'EOF'
0000000000000000 <probe>:
   0:	mov    0x0(%rip),%rax        # 7 <probe+0x7>
   7:	call   c <probe+0xc>
   c:	xor    %eax,%eax
   e:	xor    %edx,%edx
  10:	pxor   %xmm0,%xmm0
  14:	ret
EOF
)

expect "AArch64, LLVM objdump, Mach-O alias, CRLF line ends" probe \
  'ret: v0 x0' < <(crlf <<'EOF'
0000000000000000 <ltmp0>:
0000000000000000 <_probe>:
       0: 	mov	x0, #0
       4: 	movi.2d	v0, #0000000000000000
       8: 	ret
EOF
)

expect "x86-64, GNU objdump, COFF: section headers between functions" probe \
  'ret: r8 rax rcx xmm5' <<'EOF'

Disassembly of section .text$other:

0000000000000000 <other>:
   0:	xor    %eax,%eax
   2:	ret

Disassembly of section .text$probe:

0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	xor    %ecx,%ecx
   4:	xor    %r8d,%r8d
   7:	pxor   %xmm5,%xmm5
   b:	ret
   c:	nopl   0x0(%rax)
EOF

# Jumps out (report=exits). A path that leaves the function by a jump
# skips its register clearing; the default report does not see it.
cold1=$(cat <<'EOF'
0000000000000000 <f>:
   0:	test   %edi,%edi
   2:	jne    10 <f.cold>
   4:	xor    %eax,%eax
   6:	ret

0000000000000010 <f.cold>:
  10:	mov    $0x2a,%eax
  15:	jmp    6 <f+0x6>
EOF
)
expect "a cold part that rejoins the return: the default report misses it" \
  f 'ret: rax' <<< "$cold1"
expect_exits "a cold part that rejoins the return: the function's exit" \
  f 'exit: f.cold' <<< "$cold1"
expect_exits "a cold part that rejoins the return: the cold part's exit" \
  f.cold 'exit: f' <<< "$cold1"

tail1=$(cat <<'EOF'
0000000000000000 <f>:
   0:	test   %edi,%edi
   2:	je     8 <f+0x8>
   4:	jmp    20 <helper>
   6:	nop
   8:	xor    %eax,%eax
   a:	ret

0000000000000020 <helper>:
  20:	mov    $0x2a,%eax
  25:	ret
EOF
)
expect "a tail jump to a dirty helper: the default report misses it" \
  f 'ret: rax' <<< "$tail1"
expect_exits "a tail jump to a dirty helper" f 'exit: helper' <<< "$tail1"

# A cold part that ends in a call (one that raises) jumps nowhere; a call
# is not a jump out, nor is a branch within the function.
clean=$(cat <<'EOF'
0000000000000000 <_f>:
       0: 	cbnz	x1, 0x10 <_f.cold>
       4: 	b.eq	0xc <_f+0xc>
       8: 	bl	0x20 <_g>
       c: 	mov	x0, #0
      10: 	ret

0000000000000010 <_f.cold>:
      10: 	mov	x0, #0x2a
      14: 	bl	0x20 <_g>

0000000000000020 <_g>:
      20: 	ret
EOF
)
expect_exits "into its own cold part, Mach-O underscore" f 'exit: f.cold' \
  <<< "$clean"
expect_exits "a cold part that ends in a call jumps nowhere" f.cold '' \
  <<< "$clean"
expect_exits "no such function" probe 'none' <<< "$clean"

# Relocation records (objdump -r), in an object file: the jump shows a
# placeholder target and the record after it names the real one. The
# default report ignores the records.
macho=$(cat <<'EOF'
0000000000000000 <_f>:
0000000000000000 <ltmp0>:
       0:      	cbz	x1, 0x14 <ltmp0+0x14>
       4:      	bl	0x4 <ltmp0+0x4>
		0000000000000004:  ARM64_RELOC_BRANCH26	_memset
       8:      	b	0x8 <ltmp0+0x8>
		0000000000000008:  ARM64_RELOC_ADDEND	0x4
		0000000000000008:  ARM64_RELOC_BRANCH26	_f.cold
       c:      	b	0xc <ltmp0+0xc>
		000000000000000c:  ARM64_RELOC_BRANCH26	_helper
      10:      	b	0x10 <ltmp0+0x10>
		0000000000000010:  ARM64_RELOC_BRANCH26	ltmp1
      14:      	mov	x0, #0x0                ; =0
      18:      	movi.2d	v0, #0000000000000000
      1c:      	ret
EOF
)
expect "AArch64, LLVM objdump, Mach-O object: records are not instructions" \
  f 'ret: v0 x0' <<< "$macho"
expect_exits "AArch64, LLVM objdump, Mach-O object: a record names the target" \
  f $'exit: f.cold\nexit: helper\nexit: ltmp1' <<< "$macho"

# GNU, ELF: a jump into another section is relocated against the section
# symbol, with an addend.
elf=$(cat <<'EOF'
0000000000000000 <f>:
   0:	test   %edi,%edi
   2:	jne    8 <f+0x8>
			4: R_X86_64_PLT32	.text.unlikely.f-0x3
   8:	call   d <f+0xd>
			9: R_X86_64_PLT32	memcpy-0x4
   d:	je     13 <f+0x13>
			f: R_X86_64_PLT32	f-0x4
  13:	jmp    18 <f+0x18>
			14: R_X86_64_PLT32	helper-0x4
  18:	lea    0x0(%rip),%rdi        # 1f <f+0x1f>
			1b: R_X86_64_PC32	.rodata-0x4
  1f:	xor    %eax,%eax
  21:	pxor   %xmm0,%xmm0
  25:	ret
EOF
)
expect "x86-64, GNU objdump, ELF object: records are not instructions" \
  f 'ret: rax xmm0' <<< "$elf"
expect_exits "x86-64, GNU objdump, ELF object: a record names the target" \
  f $'exit: .text.unlikely.f\nexit: f-0x4\nexit: helper' <<< "$elf"

aarch64_elf=$(cat <<'EOF'
0000000000000000 <f>:
   0:	cbz	x1, 0 <f>
			0: R_AARCH64_CONDBR19	.text.unlikely.f+0x4
   4:	bl	0 <memcpy>
			4: R_AARCH64_CALL26	memcpy
   8:	mov	x0, #0x0                   	// #0
   c:	ret
  10:	b	0 <helper>
			10: R_AARCH64_JUMP26	helper
EOF
)
expect "AArch64, GNU objdump, ELF object: records are not instructions" \
  f 'ret: x0' <<< "$aarch64_elf"
expect_exits "AArch64, GNU objdump, ELF object: a record names the target" \
  f $'exit: .text.unlikely.f\nexit: helper' <<< "$aarch64_elf"

coff=$(cat <<'EOF'

Disassembly of section .text$f:

0000000000000000 <f>:
   0:	sub    $0x28,%rsp
   4:	call   9 <f+0x9>
			5: IMAGE_REL_AMD64_REL32	memcpy
   9:	test   %eax,%eax
   b:	jne    11 <f+0x11>
			d: IMAGE_REL_AMD64_REL32	helper
  11:	xor    %ecx,%ecx
  13:	add    $0x28,%rsp
  17:	ret
EOF
)
expect "x86-64, GNU objdump, COFF object, CRLF: records are not instructions" \
  f 'ret: rcx' < <(crlf <<< "$coff")
expect_exits "x86-64, GNU objdump, COFF object, CRLF: a record names the target" \
  f 'exit: helper' < <(crlf <<< "$coff")

# A record that names the function itself: the placeholder is not the
# target (here the cbz really goes to the ret at 0xc, past the clearing),
# so the jump is listed as an exit with its addend, never taken as a
# branch within the function. A section symbol (the function's own
# section) is listed like any other symbol.
self_elf=$(cat <<'EOF'
0000000000000000 <blake2b__hashing__final>:
   0:	cbz	x1, 0 <blake2b__hashing__final>
			0: R_AARCH64_CONDBR19	blake2b__hashing__final+0xc
   4:	mov	x0, #0x0                   	// #0
   8:	movi	v0.2d, #0x0
   c:	ret
EOF
)
expect_exits "AArch64, GNU objdump, ELF object: a record names the function" \
  blake2b__hashing__final 'exit: blake2b__hashing__final+0xc' <<< "$self_elf"

expect_exits "AArch64, GNU objdump, ELF object: a record names its section" \
  f $'exit: .text.f' <<'EOF'
0000000000000000 <f>:
   0:	cbz	x1, 0 <f>
			0: R_AARCH64_CONDBR19	.text.f+0xc
   4:	mov	x0, #0x0                   	// #0
   8:	ret
EOF

expect_exits "x86-64, GNU objdump, COFF object: a record names the function" \
  f $'exit: .text$f\nexit: f' < <(crlf <<'EOF'

Disassembly of section .text$f:

0000000000000000 <f>:
   0:	test   %edi,%edi
   2:	jne    8 <f+0x8>
			4: IMAGE_REL_AMD64_REL32	f
   8:	je     e <f+0xe>
			a: IMAGE_REL_AMD64_REL32	.text$f
   e:	xor    %eax,%eax
  10:	ret
EOF
)

expect_exits "AArch64, LLVM objdump, Mach-O object: a record names the function" \
  f $'exit: f+0xc\nexit: ltmp0' <<'EOF'
0000000000000000 <_f>:
0000000000000000 <ltmp0>:
       0:      	cbz	x1, 0x0 <ltmp0>
		0000000000000000:  ARM64_RELOC_ADDEND	0xc
		0000000000000000:  ARM64_RELOC_BRANCH19	_f
       4:      	b	0x4 <ltmp0+0x4>
		0000000000000004:  ARM64_RELOC_BRANCH26	ltmp0
       8:      	mov	x0, #0x0                ; =0
       c:      	ret
EOF

# Indirect jumps: the target is not known, so each function with one
# lists it as "*indirect*". Calls (call *, blr) and returns (ret x30,
# retaa) are not jumps.
expect_exits "x86-64, GNU objdump: indirect jumps" f 'exit: *indirect*' <<'EOF'
0000000000000000 <f>:
   0:	jmp    *%rax
   2:	notrack jmp *%rcx
   5:	jmp    *0x8(%rip)        # 13 <f+0x13>
   b:	ret
EOF

expect_exits "x86-64, GNU objdump: an indirect jump after a rex.W prefix" f \
  'exit: *indirect*' <<'EOF'
0000000000000000 <f>:
   0:	rex.W jmp *%rdx
   3:	ret
EOF

expect_exits "x86-64, LLVM objdump: an indirect jump" f 'exit: *indirect*' <<'EOF'
0000000000000000 <_f>:
       0:	jmpq	*%rax
       2:	retq
EOF

expect_exits "x86-64, GNU objdump, ELF object: an indirect jump with a record" \
  f $'exit: *indirect*' <<'EOF'
0000000000000000 <f>:
   0:	jmp    *0x0(%rip)        # 6 <f+0x6>
			2: R_X86_64_GOTPCRELX	helper-0x4
EOF

expect_exits "AArch64: br, including the veneer registers, and braaz" \
  f 'exit: *indirect*' <<'EOF'
0000000000000000 <f>:
   0:	br	x1
   4:	br	x16
   8:	br	x17
   c:	braaz	x2
EOF

expect_exits "a cold part that ends in an indirect jump, with no return" \
  f.cold 'exit: *indirect*' <<'EOF'
0000000000000000 <f.cold>:
   0:	mov	x0, #0x2a                  	// #42
   4:	br	x1
EOF

expect_exits "calls through registers and returns are not jumps" f '' <<'EOF'
0000000000000000 <f>:
   0:	blr	x1
   4:	blraaz	x2
   8:	bl	0 <g>
   c:	ret	x30
  10:	retaa
  14:	ret
EOF

expect_exits "x86-64: calls through registers and returns are not jumps" \
  f '' <<'EOF'
0000000000000000 <f>:
   0:	call   *%rax
   2:	call   *0x8(%rip)        # 10 <f+0x10>
   8:	ret    $0x8
   b:	ret
EOF

# The architecture is told by the % of AT&T register names. An x86-64 cold
# part with no register operand at all is still read as x86-64: its jump
# back into the function is listed, and its indirect jump through an
# absolute address too.
expect_exits "x86-64: a cold part with no register operand" f.cold \
  $'exit: *indirect*\nexit: f' <<'EOF'
0000000000000000 <f>:
   0:	xor    %eax,%eax
   2:	ret

0000000000000010 <f.cold>:
  10:	jmp    2 <f+0x2>
  12:	jmp    *0x601000
EOF

# Falling off the end: a function whose last instruction (after trailing
# padding) is not a return, an unconditional jump, a trap or a call runs
# into whatever follows it.
expect_exits "AArch64: a cold part that falls through after a mov" f.cold \
  'exit: *falls-through* mov x0, #0x2a' <<'EOF'
0000000000000000 <f.cold>:
   0:	cbz	x1, 8 <f.cold+0x8>
   4:	ret
   8:	mov	x0, #0x2a                  	// #42

0000000000000010 <g>:
  10:	ret
EOF

expect_exits "x86-64: a conditional jump as the last instruction" f \
  'exit: *falls-through* jne 0 <f>' <<'EOF'
0000000000000000 <f>:
   0:	xor    %eax,%eax
   2:	jne    0 <f>
EOF

expect_exits "x86-64, CRLF: a mov after nop padding" f \
  'exit: *falls-through* mov $0x2a,%eax' < <(crlf <<'EOF'
0000000000000000 <f>:
   0:	mov    $0x2a,%eax
   5:	nopl   0x0(%rax)
EOF
)

expect_exits "a function of nothing but padding" f \
  'exit: *falls-through* (nothing but padding)' <<'EOF'
0000000000000000 <f>:
   0:	nop
   4:	nop
EOF

expect_exits "a function with no instruction" f \
  'exit: *falls-through* (no instruction)' <<'EOF'
0000000000000000 <f>:

0000000000000010 <g>:
  10:	ret
EOF

expect_exits "x86-64, GNU: a cold part that ends in a call" f.cold '' <<'EOF'
0000000000000000 <f.cold>:
   0:	mov    $0x2a,%edi
   5:	call   a <f.cold+0xa>
EOF

expect_exits "AArch64: a cold part that ends in brk" f.cold '' <<'EOF'
0000000000000000 <f.cold>:
   0:	mov	x0, #0x2a                  	// #42
   4:	brk	#0x3e8
EOF

expect_exits "AArch64, GNU: a cold part that ends in udf" f.cold '' <<'EOF'
0000000000000000 <f.cold>:
   0:	mov	x0, #0x2a                  	// #42
   4:	udf	#0
EOF

expect_exits "x86-64: a cold part that ends in ud2" f.cold '' <<'EOF'
0000000000000000 <f.cold>:
   0:	mov    $0x2a,%eax
   5:	ud2
EOF

expect_exits "x86-64, GNU: a return followed by nop padding" f '' <<'EOF'
0000000000000000 <f>:
   0:	xor    %eax,%eax
   2:	ret
   3:	data16 cs nopw 0x0(%rax,%rax,1)
   e:	xchg   %ax,%ax
  10:	nopl   0x0(%rax)
EOF

expect_exits "x86-64: a jump followed by int3 padding" f.cold 'exit: f' <<'EOF'
0000000000000000 <f>:
   0:	xor    %eax,%eax
   2:	ret

0000000000000010 <f.cold>:
  10:	mov    $0x2a,%eax
  15:	jmp    2 <f+0x2>
  17:	int3
EOF

expect_exits "AArch64, LLVM: a return followed by nop padding" f '' <<'EOF'
0000000000000000 <_f>:
       0: 	mov	x0, #0
       4: 	ret
       8: 	nop
       c: 	nop
EOF

echo "zeroed-at-return: $pass passed, $bad failed"
[ "$bad" -eq 0 ]
