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
# indirect jumps, listed as "*indirect*"; calls through a register or
# memory (blr, blraa, call *%rax, call *0x0(%rip) with a GOT or import
# record), listed as "*indirect-call*", but not direct calls, with or
# without a record, or returns; and a function that runs off its end,
# listed as "*falls-through*" with its last instruction (an undecoded word
# included), but not one that ends in a return, an unconditional jump, a
# trap or a call, before any nop padding. A word the disassembler could
# not decode (GNU's .inst and (bad), LLVM's <unknown>, data printed as
# .word or .byte) empties the register span. Then the third report,
# the instructions that give a function a stack frame (report=frame), as
# check-hardening.sh reads the wipe routines: a frameless zeroing leaf
# (the real ones, on each format) lists nothing; a push, a pop, an
# adjustment of the stack pointer, an access relative to the stack or
# frame pointer (x86-64 red zone included), a call, an instruction whose
# destinations cannot be told and an undecoded word are each listed, a
# conditional branch (b.ne, bc.eq) and a symbol label that merely
# contains "sp" are not, and a function not in the input is "none".
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

# The same for the third report, the stack frame (report=frame).
expect_frame () {
  check "$1" "$3" \
    "$(awk -v fn="$2" -v report=frame -f scripts/zeroed-at-return.awk)"
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

# A word the disassembler could not decode may write anything, so it
# empties the span like cpuid: GNU's .inst (AArch64) and (bad) (x86-64),
# LLVM's <unknown>, and data printed as a directive.
expect "AArch64, GNU objdump: an undecoded word (.inst) empties the span" \
  probe 'ret: x1' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0                   	// #0
   4:	.inst	0x00b0d7f0 ; undefined
   8:	mov	x1, #0x0                   	// #0
   c:	ret
EOF

expect "AArch64, LLVM objdump: <unknown> and .word empty the span" probe \
  'ret: x2' <<'EOF'
0000000000000000 <_probe>:
       0: 	mov	x0, #0
       4: 	<unknown>
       8: 	mov	x1, #0
       c: 	.word	0x00b0d7f0
      10: 	mov	x2, #0
      14: 	ret
EOF

expect "x86-64, GNU objdump: (bad) and .byte empty the span" probe \
  'ret: rdx' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	(bad)
   3:	xor    %ecx,%ecx
   5:	.byte 0x8f
   6:	xor    %edx,%edx
   8:	ret
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

expect_exits "AArch64: a direct call and returns are not exits" f '' <<'EOF'
0000000000000000 <f>:
   0:	bl	0 <g>
   4:	ret	x30
   8:	retaa
   c:	ret
EOF

expect_exits "x86-64: a direct call with a record and returns are not exits" \
  f '' <<'EOF'
0000000000000000 <f>:
   0:	call   5 <f+0x5>
			1: R_X86_64_PLT32	memcpy-0x4
   5:	ret    $0x8
   8:	ret
EOF

# Calls through a register or memory: the target is not known, so each
# function with one lists it once as "*indirect-call*", whatever record
# follows it (a GOT or import slot names a symbol, but the call goes
# wherever the slot points). Direct calls beside them stay unlisted.
expect_exits "AArch64, GNU objdump: blr, blraa and blraaz" f \
  'exit: *indirect-call*' <<'EOF'
0000000000000000 <f>:
   0:	blr	x8
   4:	blraa	x8, x9
   8:	blraaz	x1
   c:	bl	0 <g>
			c: R_AARCH64_CALL26	g
  10:	ret
EOF

expect_exits "AArch64, LLVM objdump, Mach-O object: blr beside a direct bl" f \
  'exit: *indirect-call*' <<'EOF'
0000000000000000 <_f>:
0000000000000000 <ltmp0>:
       0:      	bl	0x0 <ltmp0>
		0000000000000000:  ARM64_RELOC_BRANCH26	_memset
       4:      	blr	x8
       8:      	blrab	x8, x9
       c:      	ret
EOF

expect_exits "x86-64, GNU objdump: calls through a register and memory" f \
  'exit: *indirect-call*' <<'EOF'
0000000000000000 <f>:
   0:	call   *%rax
   2:	notrack call *%rcx
   5:	call   *0x8(%rax)
   8:	call   *0x8(%rip)        # 16 <f+0x16>
   e:	ret
EOF

expect_exits "x86-64, GNU objdump, ELF object: a call through the GOT" f \
  'exit: *indirect-call*' <<'EOF'
0000000000000000 <f>:
   0:	call   *0x0(%rip)        # 6 <f+0x6>
			2: R_X86_64_GOTPCRELX	memcpy-0x4
   6:	call   b <f+0xb>
			7: R_X86_64_PLT32	_Unwind_Resume-0x4
   b:	ret
EOF

expect_exits "x86-64, GNU objdump, COFF object, CRLF: a call through an import" \
  f 'exit: *indirect-call*' < <(crlf <<'EOF'

Disassembly of section .text$f:

0000000000000000 <f>:
   0:	sub    $0x28,%rsp
   4:	call   *0x0(%rip)        # a <f+0xa>
			6: IMAGE_REL_AMD64_REL32	__imp_memcpy
   a:	add    $0x28,%rsp
   e:	ret
EOF
)

expect_exits "x86-64, LLVM objdump: callq through a register and memory" f \
  'exit: *indirect-call*' <<'EOF'
0000000000000000 <_f>:
       0:	callq	*%rax
       2:	callq	*8(%rax)
       5:	retq
EOF

expect_exits "a cold part that ends in an indirect call" f.cold \
  'exit: *indirect-call*' <<'EOF'
0000000000000000 <f.cold>:
   0:	mov	x0, #0x2a                  	// #42
   4:	blr	x1
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

# The stack frame (report=frame). A frameless leaf (stores relative to its
# argument register, a return) lists nothing; everything that gives it a
# frame, touches the stack or calls out is listed, in order.
wipe_llvm=$(cat <<'EOF'
0000000000000000 <_blake2b__wipe__sanitize_words8>:
0000000000000000 <ltmp0>:
       0:      	movi.4s	v31, #0x0
       4:      	stp	q31, q31, [x0]
       8:      	stp	q31, q31, [x0, #0x20]
       c:      	ret

0000000000000010 <_blake2b__wipe__sanitize_block>:
      10:      	movi.4s	v31, #0x0
      14:      	stp	q31, q31, [x0]
      18:      	stp	q31, q31, [x0, #0x20]
      1c:      	stp	q31, q31, [x0, #0x40]
      20:      	stp	q31, q31, [x0, #0x60]
      24:      	ret
EOF
)
expect_frame "AArch64, LLVM objdump (macOS): the first frameless leaf" \
  blake2b__wipe__sanitize_words8 '' <<< "$wipe_llvm"
expect_frame "AArch64, LLVM objdump (macOS): the second frameless leaf" \
  blake2b__wipe__sanitize_block '' <<< "$wipe_llvm"
expect_exits "AArch64, LLVM objdump (macOS): a frameless leaf jumps nowhere" \
  blake2b__wipe__sanitize_block '' <<< "$wipe_llvm"

expect_frame "AArch64, GNU objdump (Linux): a frameless leaf" f '' <<'EOF'
0000000000000000 <f>:
   0:	movi	v31.4s, #0x0
   4:	stp	q31, q31, [x0]
   8:	stp	q31, q31, [x0, #32]
   c:	ret
EOF

expect_frame "x86-64, GNU objdump (Linux): a frameless leaf" f '' <<'EOF'
0000000000000000 <f>:
   0:	endbr64
   4:	pxor   %xmm0,%xmm0
   8:	movups %xmm0,(%rdi)
   b:	movups %xmm0,0x10(%rdi)
   f:	movq   $0x0,0x20(%rdi)
  17:	ret
  18:	nopl   0x0(%rax,%rax,1)
EOF

expect_frame "x86-64, GNU objdump, COFF, CRLF: a frameless leaf" f '' \
  < <(crlf <<'EOF'
Disassembly of section .text$f:

0000000000000000 <f>:
   0:	pxor   %xmm0,%xmm0
   4:	movups %xmm0,(%rcx)
   7:	movups %xmm0,0x10(%rcx)
   b:	ret
EOF
)

expect_frame "AArch64, GNU objdump: a frame record" f \
  $'frame: uses the stack: stp x29, x30, [sp, #-16]!\nframe: uses the stack: mov x29, sp\nframe: uses the stack: str xzr, [x29, #16]\nframe: uses the stack: ldp x29, x30, [sp], #16' <<'EOF'
0000000000000000 <f>:
   0:	stp	x29, x30, [sp, #-16]!
   4:	mov	x29, sp
   8:	str	xzr, [x29, #16]
   c:	stp	xzr, xzr, [x0]
  10:	ldp	x29, x30, [sp], #16
  14:	ret
EOF

expect_frame "AArch64, LLVM objdump: a stack adjustment and a store to it" f \
  $'frame: uses the stack: sub sp, sp, #0x10\nframe: uses the stack: str q0, [sp]\nframe: uses the stack: add sp, sp, #0x10' <<'EOF'
0000000000000000 <_f>:
       0:      	sub	sp, sp, #0x10
       4:      	movi.2d	v0, #0000000000000000
       8:      	str	q0, [sp]
       c:      	add	sp, sp, #0x10
      10:      	ret
EOF

expect_frame "AArch64: a store below sp with no adjustment, and fp by name" f \
  $'frame: uses the stack: stur xzr, [sp, #-8]\nframe: uses the stack: str wzr, [fp, #4]' <<'EOF'
0000000000000000 <f>:
   0:	stur	xzr, [sp, #-8]
   4:	str	wzr, [fp, #4]
   8:	ret
EOF

expect_frame "x86-64, GNU objdump: a frame" f \
  $'frame: uses the stack: push %rbp\nframe: uses the stack: mov %rsp,%rbp\nframe: uses the stack: sub $0x18,%rsp\nframe: uses the stack: movq $0x0,-0x8(%rbp)\nframe: uses the stack: leave' <<'EOF'
0000000000000000 <f>:
   0:	push   %rbp
   1:	mov    %rsp,%rbp
   4:	sub    $0x18,%rsp
   8:	movq   $0x0,-0x8(%rbp)
  10:	movq   $0x0,(%rdi)
  17:	leave
  18:	ret
EOF

expect_frame "x86-64, LLVM objdump: pushq, popq and pushfq" f \
  $'frame: uses the stack: pushq %rbx\nframe: uses the stack: pushfq\nframe: uses the stack: popfq\nframe: uses the stack: popq %rbx' <<'EOF'
0000000000000000 <_f>:
       0:	pushq	%rbx
       1:	pushfq
       2:	xorl	%eax, %eax
       4:	popfq
       5:	popq	%rbx
       6:	retq
EOF

expect_frame "x86-64: the red zone (a store below rsp, no adjustment)" f \
  $'frame: uses the stack: movq $0x0,-0x8(%rsp)\nframe: uses the stack: mov %eax,-0x10(%rsp,%rdx,1)\nframe: uses the stack: lea 0x8(%rsp),%rax' <<'EOF'
0000000000000000 <f>:
   0:	movq   $0x0,-0x8(%rsp)
   9:	mov    %eax,-0x10(%rsp,%rdx,1)
   d:	lea    0x8(%rsp),%rax
  12:	ret
EOF

expect_frame "x86-64: enter, and a write to a narrow view of rsp" f \
  $'frame: uses the stack: enter $0x10,$0x0\nframe: uses the stack: and $0xf0,%spl\nframe: uses the stack: mov %ebp,%eax' <<'EOF'
0000000000000000 <f>:
   0:	enter  $0x10,$0x0
   4:	and    $0xf0,%spl
   8:	mov    %ebp,%eax
   a:	ret
EOF

expect_frame "calls, direct and through a register, with a record" f \
  $'frame: calls: bl 0 <memset> (record: memset)\nframe: calls: blr x1' <<'EOF'
0000000000000000 <f>:
   0:	bl	0 <memset>
			0: R_AARCH64_CALL26	memset
   4:	blr	x1
   8:	ret
EOF

expect_frame "x86-64, GNU objdump, ELF object: a call with a record" f \
  'frame: calls: call 5 <f+0x5> (record: memset-0x4)' <<'EOF'
0000000000000000 <f>:
   0:	call   5 <f+0x5>
			1: R_X86_64_PLT32	memset-0x4
   5:	ret
EOF

expect_frame "instructions whose destinations cannot be told" f \
  $'frame: undecoded: svc #0x0\nframe: undecoded: eret' <<'EOF'
0000000000000000 <f>:
   0:	svc	#0x0
   4:	eret
   8:	ret
EOF

expect_frame "x86-64: cpuid cannot be told" f 'frame: undecoded: cpuid' <<'EOF'
0000000000000000 <f>:
   0:	xor    %eax,%eax
   2:	cpuid
   4:	ret
EOF

# A word the disassembler could not decode is never certified: it might
# be a push, a store below sp or a call.
expect_frame "AArch64, GNU objdump: .inst and .word are undecoded" f \
  $'frame: undecoded: .inst 0x00b0d7f0\nframe: undecoded: .word 0x00000000' <<'EOF'
0000000000000000 <f>:
   0:	movi	v31.4s, #0x0
   4:	.inst	0x00b0d7f0 ; undefined
   8:	stp	q31, q31, [x0]
   c:	.word	0x00000000
  10:	ret
EOF

expect_frame "AArch64, LLVM objdump: <unknown> is undecoded" f \
  'frame: undecoded: <unknown>' <<'EOF'
0000000000000000 <_f>:
       0: 	movi.4s	v31, #0x0
       4: 	<unknown>
       8: 	stp	q31, q31, [x0]
       c: 	ret
EOF

expect_frame "x86-64, GNU objdump: (bad), .byte and a (bad) operand" f \
  $'frame: undecoded: (bad)\nframe: undecoded: .byte 0x8f\nframe: undecoded: vpxor (bad),%xmm0,%xmm0' <<'EOF'
0000000000000000 <f>:
   0:	pxor   %xmm0,%xmm0
   4:	(bad)
   5:	.byte 0x8f
   6:	vpxor  (bad),%xmm0,%xmm0
   a:	movups %xmm0,(%rdi)
   d:	ret
EOF

# The conditional branches keep their condition (b.ne, bc.eq): they are
# branches, not undecoded words, and a frameless leaf with them lists
# nothing.
expect_frame "AArch64: conditional branches are not undecoded" f '' <<'EOF'
0000000000000000 <f>:
   0:	cbz	x1, 10 <f+0x10>
   4:	b.ne	10 <f+0x10>
   8:	bc.eq	10 <f+0x10>
   c:	str	xzr, [x0]
  10:	ret
EOF

expect_exits "AArch64: conditional branches within the function are no exit" \
  f '' <<'EOF'
0000000000000000 <f>:
   0:	b.ne	8 <f+0x8>
   4:	bc.eq	8 <f+0x8>
   8:	ret
EOF

expect_exits "AArch64, GNU objdump: a function that ends in an undecoded word" \
  f 'exit: *falls-through* .inst 0x00000000' <<'EOF'
0000000000000000 <f>:
   0:	mov	x0, #0x0                   	// #0
   4:	.inst	0x00000000 ; undefined
EOF

# A branch to a label that merely contains "sp" or "fp" names no register;
# jumps out are the exits report's.
expect_frame "a label that contains sp names no register" f '' <<'EOF'
0000000000000000 <f>:
   0:	cbz	x0, 8 <f_sp+0x8>
   4:	b	8 <fp>
   8:	ret
EOF

expect_frame "a function not in the input" g 'none' <<'EOF'
0000000000000000 <f>:
   0:	ret
EOF

echo "zeroed-at-return: $pass passed, $bad failed"
[ "$bad" -eq 0 ]
