#!/usr/bin/env bash
# Tests scripts/zeroed-at-return.awk, the parser check-hardening.sh uses,
# against the disassembly formats CI meets: GNU objdump (Linux, Windows)
# and LLVM objdump (macOS), on x86-64 and AArch64. That includes AArch64
# immediates, which are written "#0" like an x86 comment, and the Mach-O
# section-start aliases (ltmp0) that label a function's first address.
#
# Usage: scripts/test-zeroed-at-return.sh

set -euo pipefail
cd "$(dirname "$0")/.."

pass=0
bad=0
# Runs the parser on stdin for function $2; compares with $3.
expect () {
  local label=$1 fn=$2 want=$3 got
  got=$(awk -v fn="$fn" -f scripts/zeroed-at-return.awk)
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

echo "zeroed-at-return: $pass passed, $bad failed"
[ "$bad" -eq 0 ]
