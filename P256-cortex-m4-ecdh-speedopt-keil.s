; P-256 ECDH
; Author: Emil Lenngren
; Licensed under the BSD 2-clause license.

; Note on calling conventions: some of the local functions in this file use custom calling conventions.
; Exported symbols use the standard C calling conventions for ARM, which means that r4-r11 and sp are preserved and the other registers are clobbered.

; All integers are assumed to be in little endian

; Run time: 994k cycles

	area |.text|, code, readonly

; Field arithmetics for the prime field where p = 2^256 - 2^224 + 2^192 + 2^96 - 1
; Multiplication and Squaring use Montgomery Modular Multiplication where R = 2^256
; To convert a value to Montgomery class, use P256_mulmod(value, R^512 mod p)
; To convert a value from Montgomery class to standard form, use P256_mulmod(value, 1)

; If inputs are A*R mod p and B*R mod p, computes AB*R mod p
; *r1 = in1, *r2 = in2
; out: r0-r7
; clobbers all other registers
; cycles: 230
P256_mulmod proc
	
	push {r2,lr}
	frame push {lr}
	frame address sp,8
	
	sub sp,#36
	frame address sp,44
	ldm r2,{r2,r3,r4,r5}
	
	ldm r1!,{r0,r10,lr}
	umull r6,r11,r2,r0
	
	umull r7,r12,r3,r0
	umaal r7,r11,r2,r10
	
	push {r6,r7}
	frame address sp,52
	
	umull r8,r6,r4,r0
	umaal r8,r11,r3,r10
	
	umull r9,r7,r5,r0
	umaal r9,r11,r4,r10
	
	umaal r11,r7,r5,r10
	
	umaal r8,r12,r2,lr
	umaal r9,r12,r3,lr
	umaal r11,r12,r4,lr
	umaal r12,r7,r5,lr
	
	ldm r1!,{r0,r10,lr}
	
	umaal r9,r6,r2,r0
	umaal r11,r6,r3,r0
	umaal r12,r6,r4,r0
	umaal r6,r7,r5,r0
	
	strd r8,r9,[sp,#8]
	
	mov r9,#0
	umaal r11,r9,r2,r10
	umaal r12,r9,r3,r10
	umaal r6,r9,r4,r10
	umaal r7,r9,r5,r10
	
	mov r10,#0
	umaal r12,r10,r2,lr
	umaal r6,r10,r3,lr
	umaal r7,r10,r4,lr
	umaal r9,r10,r5,lr
	
	ldr r8,[r1],#4
	mov lr,#0
	umaal lr,r6,r2,r8
	umaal r7,r6,r3,r8
	umaal r9,r6,r4,r8
	umaal r10,r6,r5,r8
	
	;_ _ _ _ _ 6 10 9| 7 | lr 12 11 _ _ _ _
	
	ldr r8,[r1],#-28
	mov r0,#0
	umaal r7,r0,r2,r8
	umaal r9,r0,r3,r8
	umaal r10,r0,r4,r8
	umaal r6,r0,r5,r8
	
	push {r0}
	frame address sp,56
	
	;_ _ _ _ s 6 10 9| 7 | lr 12 11 _ _ _ _
	
	ldr r2,[sp,#48]
	adds r2,r2,#16
	ldm r2,{r2,r3,r4,r5}
	
	ldr r8,[r1],#4
	mov r0,#0
	umaal r11,r0,r2,r8
	str r11,[sp,#16+4]
	umaal r12,r0,r3,r8
	umaal lr,r0,r4,r8
	umaal r0,r7,r5,r8 ; 7=carry for 9
	
	;_ _ _ _ s 6 10 9+7| 0 | lr 12 _ _ _ _ _
	
	ldr r8,[r1],#4
	mov r11,#0
	umaal r12,r11,r2,r8
	str r12,[sp,#20+4]
	umaal lr,r11,r3,r8
	umaal r0,r11,r4,r8
	umaal r11,r7,r5,r8 ; 7=carry for 10
	
	;_ _ _ _ s 6 10+7 9+11| 0 | lr _ _ _ _ _ _
	
	ldr r8,[r1],#4
	mov r12,#0
	umaal lr,r12,r2,r8
	str lr,[sp,#24+4]
	umaal r0,r12,r3,r8
	umaal r11,r12,r4,r8
	umaal r10,r12,r5,r8 ; 12=carry for 6
	
	;_ _ _ _ s 6+12 10+7 9+11| 0 | _ _ _ _ _ _ _
	
	ldr r8,[r1],#4
	mov lr,#0
	umaal r0,lr,r2,r8
	str r0,[sp,#28+4]
	umaal r11,lr,r3,r8
	umaal r10,lr,r4,r8
	umaal r6,lr,r5,r8 ; lr=carry for saved
	
	;_ _ _ _ s+lr 6+12 10+7 9+11| _ | _ _ _ _ _ _ _
	
	ldm r1!,{r0,r8}
	umaal r11,r9,r2,r0
	str r11,[sp,#32+4]
	umaal r9,r10,r3,r0
	umaal r10,r6,r4,r0
	pop {r11}
	frame address sp,52
	umaal r11,r6,r5,r0 ; 6=carry for next
	
	;_ _ _ 6 11+lr 10+12 9+7 _ | _ | _ _ _ _ _ _ _
	
	umaal r9,r7,r2,r8
	umaal r10,r7,r3,r8
	umaal r11,r7,r4,r8
	umaal r6,r7,r5,r8
	
	ldm r1!,{r0,r8}
	umaal r10,r12,r2,r0
	umaal r11,r12,r3,r0
	umaal r6,r12,r4,r0
	umaal r7,r12,r5,r0
	
	umaal r11,lr,r2,r8
	umaal lr,r6,r3,r8
	umaal r6,r7,r4,r8
	umaal r7,r12,r5,r8
	
	; 12 7 6 lr 11 10 9 stack*9
	strd r6,r7,[sp,#36]
	str r12,[sp,#44]
	pop {r0-r8}
	frame address sp,16
	
	mov r12,#0

	adds r3,r0
	adcs r4,r1
	adcs r5,r2
	adcs r6,r0
	adcs r7,r1
	adcs r8,r0
	adcs r9,r1
	adcs r10,#0
	adcs r11,#0
	adcs r12,#0

	adds r6,r3
	adcs r7,r4 ; r4 instead of 0
	adcs r8,r2
	adcs r9,r3
	adcs r10,r2
	adcs r11,r3
	adcs r12,#0

	subs r7,r0
	sbcs r8,r1
	sbcs r9,r2
	sbcs r10,r3
	sbcs r11,#0
	sbcs r12,#0 ; r12 is between 0 and 2

	pop {r1-r3}
	frame address sp,4

	adds r0,lr,r12
	adcs r1,#0
	mov r12,#0
	adcs r12,#0

	;adds r7,r4 (added above instead)
	adcs r8,r5
	adcs r9,r6
	adcs r10,r4
	adcs r11,r5
	adcs r0,r4
	adcs r1,r5
	adcs r2,r12
	adcs r3,#0
	mov r12,#0
	adcs r12,#0

	adcs r10,r7
	adcs r11,#0
	adcs r0,r6
	adcs r1,r7
	adcs r2,r6
	adcs r3,r7
	adcs r12,#0

	subs r11,r4
	sbcs r0,r5
	sbcs r1,r6
	sbcs r2,r7
	sbcs r3,#0
	sbcs r12,#0
	
	; now (T + mN) / R is
	; 8 9 10 11 0 1 2 3 12 (lsb -> msb)
	
	subs r8,r8,#0xffffffff
	sbcs r9,r9,#0xffffffff
	sbcs r10,r10,#0xffffffff
	sbcs r11,r11,#0
	sbcs r4,r0,#0
	sbcs r5,r1,#0
	sbcs r6,r2,#1
	sbcs r7,r3,#0xffffffff
	sbc r12,r12,#0
	
	adds r0,r8,r12
	adcs r1,r9,r12
	adcs r2,r10,r12
	adcs r3,r11,#0
	adcs r4,r4,#0
	adcs r5,r5,#0
	adcs r6,r6,r12, lsr #31
	adcs r7,r7,r12
	
	pop {pc}
	
	endp

; 172 cycles
; If input is A*R mod p, computes A^2*R mod p
; in/out: r0-r7
; clobbers all other registers
P256_sqrmod proc
	push {lr}
	frame push {lr}
	
	;mul 01, 00
	umull r10,r9,r0,r0
	umull r11,r12,r0,r1
	adds r11,r11,r11
	mov lr,#0
	umaal r9,r11,lr,lr
	
	;r9 r10 done
	;r12 carry for 3rd before col
	;r11+C carry for 3rd final col
	
	push {r9,r10}
	frame address sp,12
	
	;mul 02, 11
	mov r9,#0
	umaal r9,r12,r0,r2
	adcs r9,r9,r9
	umaal r9,r11,r1,r1
	
	;r9 done (3rd col)
	;r12 carry for 4th before col
	;r11+C carry for 4th final col
	
	;mul 03, 12
	umull r8,r10,r0,r3
	umaal r8,r12,r1,r2
	adcs r8,r8,r8
	umaal r8,r11,lr,lr
	
	;r8 done (4th col)
	;r10+r12 carry for 5th before col
	;r11+C carry for 5th final col
	
	push {r8,r9}
	frame address sp,20
	
	;mul 04, 13, 22
	mov r9,#0
	umaal r9,r10,r0,r4
	umaal r9,r12,r1,r3
	adcs r9,r9,r9
	umaal r9,r11,r2,r2
	
	;r9 done (5th col)
	;r10+r12 carry for 6th before col
	;r11+C carry for 6th final col
	
	push {r9}
	frame address sp,24
	
	;mul 05, 14, 23
	umull r9,r8,r0,r5
	umaal r9,r10,r1,r4
	umaal r9,r12,r2,r3
	adcs r9,r9,r9
	umaal r9,r11,lr,lr
	
	;r9 done (6th col)
	;r10+r12+r8 carry for 7th before col
	;r11+C carry for 7th final col
	
	push {r9}
	frame address sp,28
	
	;mul 06, 15, 24, 33
	mov r9,#0
	umaal r9,r8,r1,r5
	umaal r9,r12,r2,r4
	umaal r9,r10,r0,r6
	adcs r9,r9,r9
	umaal r9,r11,r3,r3
	
	;r9 done (7th col)
	;r8+r10+r12 carry for 8th before col
	;r11+C carry for 8th final col
	
	push {r9}
	frame address sp,32
	
	;mul 07, 16, 25, 34
	umull r9,r0,r0,r7
	umaal r9,r10,r1,r6
	umaal r9,r12,r2,r5
	umaal r9,r8,r3,r4
	adcs r9,r9,r9
	umaal r9,r11,lr,lr
	
	;r9 done (8th col)
	;r0+r8+r10+r12 carry for 9th before col
	;r11+C carry for 9th final col
	
	;mul 17, 26, 35, 44
	umaal r0,r8,r1,r7 ;r1 is now dead
	umaal r0,r10,r2,r6
	umaal r0,r12,r3,r5
	adcs r0,r0,r0
	umaal r11,r0,r4,r4
	
	;r11 done (9th col)
	;r8+r10+r12 carry for 10th before col
	;r0+C carry for 10th final col
	
	;mul 27, 36, 45
	umaal r12,r8,r2,r7 ;r2 is now dead
	umaal r12,r10,r3,r6
	movs r2,#0
	umaal r12,r2,r4,r5
	adcs r1,r12,r12
	umaal r0,r1,lr,lr
	
	;r0 done (10th col)
	;r8+r10+r2 carry for 11th before col
	;r1+C carry for 11th final col
	
	;mul 37, 46, 55
	umaal r2,r8,r3,r7 ;r3 is now dead
	umaal r2,r10,r4,r6
	adcs r2,r2,r2
	umaal r1,r2,r5,r5
	
	;r1 done (11th col)
	;r8+r10 carry for 12th before col
	;r2+C carry for 12th final col
	
	;mul 47, 56
	movs r3,#0
	umaal r3,r8,r4,r7 ;r4 is now dead
	umaal r3,r10,r5,r6
	adcs r3,r3,r3
	umaal r2,r3,lr,lr
	
	;r2 done (12th col)
	;r8+r10 carry for 13th before col
	;r3+C carry for 13th final col
	
	;mul 57, 66
	umaal r8,r10,r5,r7 ;r5 is now dead
	adcs r8,r8,r8
	umaal r3,r8,r6,r6
	
	;r3 done (13th col)
	;r10 carry for 14th before col
	;r8+C carry for 14th final col
	
	;mul 67
	umull r4,r5,lr,lr ; set 0
	umaal r4,r10,r6,r7
	adcs r4,r4,r4
	umaal r4,r8,lr,lr
	
	;r4 done (14th col)
	;r10 carry for 15th before col
	;r8+C carry for 15th final col
	
	;mul 77
	adcs r10,r10,r10
	umaal r8,r10,r7,r7
	adcs r10,r10,lr
	
	;r8 done (15th col)
	;r10 done (16th col)
	
	;msb -> lsb: r10 r8 r4 r3 r2 r1 r0 r11 r9 sp sp+4 sp+8 sp+12 sp+16 sp+20 sp+24
	;now do reduction
	
	push {r4,r8,r10}
	frame address sp,44
	add r4,sp,#12
	ldm r4,{r4-r8,r10,r12}
	;lr is already 0
X0 RN 12
X1 RN 10
X2 RN 8
X3 RN 7
X4 RN 6
X5 RN 5
X6 RN 4
X7 RN 9
X8 RN 11
X9 RN 0
X10 RN 1
X11 RN 2
X12 RN 3

X13 RN 7
X14 RN 8
X15 RN 10

	adcs X3,X0
	adcs X4,X1
	adcs X5,X2
	adcs X6,X0
	adcs X7,X1
	adcs X8,X0
	adcs X9,X1
	adcs X10,#0
	adcs X11,#0
	adcs lr,#0

	adds X6,X3
	adcs X7,X4 ; X4 instead of 0
	adcs X8,X2
	adcs X9,X3
	adcs X10,X2
	adcs X11,X3
	adcs lr,#0

	subs X7,X0
	sbcs X8,X1
	sbcs X9,X2
	sbcs X10,X3
	sbcs X11,#0
	sbcs lr,#0 ; lr is between 0 and 2
	
	pop {X13,X14,X15}
	frame address sp,32

	adds X0,X12,lr
	adcs X13,#0
	mov lr,#0
	adcs lr,#0

	;adds X7,X4 (added above instead)
	adcs X8,X5
	adcs X9,X6
	adcs X10,X4
	adcs X11,X5
	adcs X0,X4
	adcs X13,X5
	adcs X14,lr
	adcs X15,#0
	mov lr,#0
	adcs lr,#0

	adcs X10,X7
	adcs X11,#0
	adcs X0,X6
	adcs X13,X7
	adcs X14,X6
	adcs X15,X7
	adcs lr,#0

	subs X11,X4
	sbcs X0,X5
	sbcs X13,X6
	sbcs X14,X7
	sbcs X15,#0
	sbcs lr,#0
	
	; now (T + mN) / R is
	; X8 X9 X10 X11 X0 X13 X14 X15 lr (lsb -> msb)
	; r11 r0 r1 r2 r12 r7 r8 r10 lr
	
	subs r11,r11,#0xffffffff
	sbcs r9,r0,#0xffffffff
	sbcs r4,r1,#0xffffffff
	sbcs r3,r2,#0
	sbcs r6,r12,#0
	sbcs r5,r7,#0
	sbcs r12,r8,#1
	sbcs r8,r10,#0xffffffff
	sbcs r7,lr,#0
	
	adds r0,r11,r7
	adcs r1,r9,r7
	adcs r2,r4,r7
	adcs r3,r3,#0
	adcs r4,r6,#0
	adcs r5,r5,#0
	adcs r6,r12,r7, lsr #31
	adcs r7,r8,r7
	
	add sp,#28
	frame address sp,4
	pop {pc}
	
	endp

; in/out: r0-r7, r8: count, *r9: operand for final multiplication
P256_sqrmod_many_and_mulmod proc
	push {r9,lr}
	frame push {r9,lr}
	cmp r8,#0
	beq %f1
0
	push {r8}
	frame address sp,12
	bl P256_sqrmod
	pop {r8}
	frame address sp,8
	subs r8,#1
	bne %b0
1
	
	push {r0-r7}
	frame address sp,40
	mov r1,sp
	ldr r2,[sp,#32]
	bl P256_mulmod
	add sp,#36
	frame address sp,4
	pop {pc}
	endp


P256_invtbl
	dcb ((8-4)>>2)
	dcb 32
	
	dcb ((16-8)>>2)+128
	dcb 0
	
	dcb (16>>2)+128
	dcb 0
	
	dcb (32>>2)+128
	dcb 5*32
	
	dcb (192-64)>>2
	dcb 0
	
	dcb (224-192)>>2
	dcb 0
	
	dcb (240-224)>>2
	dcb 32
	
	dcb (248-240)>>2
	dcb 64
	
	dcb (252-248)>>2
	dcb 128
	
	dcb (256-252)>>2
	dcb 96
	
	dcb 0
	dcb 5*32

; in: r0-r7 = value
; out: r0-r7
; for modinv, call input a, then if a = A * R % p, then it calculates A^-1 * R % p = (a/R)^-1 * R % p = R^2 / a % p
P256_modinv proc
	push {r0-r7,lr}
	frame push {r4-r7,lr}
	frame address sp,36
	
	; t = a^2*a
	mov r8,#1
	mov r9,sp
	bl P256_sqrmod_many_and_mulmod
	push {r0-r7}
	frame address sp,68
	
	; a4_2 = a2_0^(2^2)
	bl P256_sqrmod
	bl P256_sqrmod
	push {r0-r7}
	frame address sp,100
	
	; a4_0 = a4_2*a2_0
	mov r1,sp
	add r2,sp,#32
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	mov r12,#0
0
	adr r9,P256_invtbl
	ldrsb r10,[r9,r12]
	add r9,#1
	ldrb r9,[r9,r12]
	lsls r8,r10,#2
	bpl %f1
	push {r0-r7}
1
	and r8,#0xff
	add r9,sp
	push {r12}
	bl P256_sqrmod_many_and_mulmod
	pop {r12}
	add r12,#2
	cmp r12,#22
	bne %b0

	add sp,#6*32
	frame address sp,4
	
	pop {pc}
	
	endp

; 52 cycles
; Computes A + B mod p, assumes A, B < p
; in: *r1, *r2
; out: r0-r7
; clobbers all other registers
P256_addmod proc
	ldm r2,{r2-r9}
	ldm r1!,{r0,r10,r11,r12}
	adds r2,r0
	adcs r3,r10
	adcs r4,r11
	adcs r5,r12
	ldm r1,{r0,r1,r11,r12}
	adcs r6,r0
	adcs r7,r1
	adcs r8,r11
	adcs r9,r12
	movs r10,#0
	adcs r10,r10
	
	subs r2,#0xffffffff
	sbcs r3,#0xffffffff
	sbcs r4,#0xffffffff
	sbcs r5,#0
	sbcs r6,#0
	sbcs r7,#0
	sbcs r8,#1
	sbcs r9,#0xffffffff
	sbcs r10,#0
	
	adds r0,r2,r10
	adcs r1,r3,r10
	adcs r2,r4,r10
	adcs r3,r5,#0
	adcs r4,r6,#0
	adcs r5,r7,#0
	adcs r6,r8,r10, lsr #31
	adcs r7,r9,r10
	
	bx lr
	
	endp

; 42 cycles
; Computes A - B mod p, assumes A, B < p
; in: *r1, *r2
; out: r0-r7
; clobbers all other registers
P256_submod proc
	ldm r1,{r3-r10}
	ldm r2!,{r0,r1,r11,r12}
	subs r3,r0
	sbcs r4,r1
	sbcs r5,r11
	sbcs r6,r12
	ldm r2,{r0,r1,r11,r12}
	sbcs r7,r0
	sbcs r8,r1
	sbcs r9,r11
	sbcs r10,r12
	
	sbcs r11,r11
	
	adds r0,r3,r11
	adcs r1,r4,r11
	adcs r2,r5,r11
	adcs r3,r6,#0
	adcs r4,r7,#0
	adcs r5,r8,#0
	adcs r6,r9,r11, lsr #31
	adcs r7,r10,r11
	
	bx lr
	
	endp

; 33 cycles
; in: r0-r7
P256_times2 proc
	adds r0,r0
	adcs r1,r1
	adcs r2,r2
	adcs r3,r3
	adcs r4,r4
	adcs r5,r5
	adcs r6,r6
	adcs r7,r7
	mov r8,#0
	adcs r8,r8
	
	subs r0,#0xffffffff
	sbcs r1,#0xffffffff
	sbcs r2,#0xffffffff
	sbcs r3,#0
	sbcs r4,#0
	sbcs r5,#0
	sbcs r6,#1
	sbcs r7,#0xffffffff
	sbcs r8,#0
	
	adds r0,r8
	adcs r1,r8
	adcs r2,r8
	adcs r3,#0
	adcs r4,#0
	adcs r5,#0
	adcs r6,r6,r8, lsr #31
	adcs r7,r8
	
	bx lr
	endp

	align 4
	; (2^256)^2 mod p
R2_mod_p
	dcd 3
	dcd 0
	dcd 0xffffffff
	dcd 0xfffffffb
	dcd 0xfffffffe
	dcd 0xffffffff
	dcd 0xfffffffd
	dcd 4

; in: *r1
; out: *r0
P256_to_montgomery proc
	push {r0,r4-r11,lr}
	frame push {r4-r11,lr}
	frame address sp,40
	adr r2,R2_mod_p
	bl P256_mulmod
	pop {r8}
	frame address sp,36
	stm r8,{r0-r7}
	pop {r4-r11,pc}
	endp

; in: *r1
; out: *r0
P256_from_montgomery proc
	push {r0,r4-r11,lr}
	frame push {r4-r11,lr}
	frame address sp,40
	movs r2,#0
	movs r3,#0
	push {r2-r3}
	frame address sp,48
	push {r2-r3}
	frame address sp,56
	push {r2-r3}
	frame address sp,64
	movs r2,#1
	push {r2-r3}
	frame address sp,72
	mov r2,sp
	bl P256_mulmod
	add sp,#32
	frame address sp,40
	pop {r8}
	frame address sp,36
	stm r8,{r0-r7}
	pop {r4-r11,pc}
	endp

; Elliptic curve operations on the NIST curve P256

; Checks if a point is on curve
; in: *r0 = x, *r1 = y, in Montgomery form
; out: r0 = 1 if on curve, else 0
P256_point_is_on_curve proc
	push {r0,r4-r11,lr}
	frame push {r4-r11,lr}
	frame address sp,40
	
	; We verify y^2 - (x^3 - 3x) = b
	
	; y^2
	ldm r1,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	frame address sp,72
	
	; x^2
	ldr r0,[sp,#32]
	ldm r0,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	frame address sp,104
	
	; x^3
	ldr r1,[sp,#64]
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	; x^3 - 3x
	movs r0,#3
0
	push {r0}
	frame address sp,108
	add r1,sp,#4
	ldr r2,[sp,#68]
	bl P256_submod
	add r8,sp,#4
	stm r8,{r0-r7}
	pop {r0}
	frame address sp,104
	subs r0,#1
	bne %b0
	
	; y^2 - (x^3 - 3x)
	add r1,sp,#32
	mov r2,sp
	bl P256_submod
	
	; compare with b
	adr r8,P256_b_mont
	ldm r8!,{r9-r12}
	eors r0,r9
	ittt eq
	eorseq r1,r10
	eorseq r2,r11
	eorseq r3,r12
	ldm r8,{r9-r12}
	itttt eq
	eorseq r4,r9
	eorseq r5,r10
	eorseq r6,r11
	eorseq r7,r12
	mov r0,#0
	it eq
	moveq r0,#1
	
	add sp,#68
	frame address sp,36
	
	pop {r4-r11,pc}
	
	endp

	align 4
P256_b_mont
	dcd 0x29c4bddf
	dcd 0xd89cdf62
	dcd 0x78843090
	dcd 0xacf005cd
	dcd 0xf7212ed6
	dcd 0xe5a220ab
	dcd 0x04874834
	dcd 0xdc30061d


; Selects one of many values
; *r0 = output, *r1 = table, r2 = index to choose [0..7]
P256_select proc
	mov r3,r2
	movs r2,#3
	push {r0,r2,r3,r4-r11,lr}
	frame push {r4-r11,lr}
	frame address sp,48

0
	rsbs r3,#0
	sbcs r3,r3
	mvns r3,r3
	
	ldm r1!,{r4-r11}
	ands r4,r3
	ands r5,r3
	ands r6,r3
	ands r7,r3
	and r8,r3
	and r9,r3
	and r10,r3
	and r11,r3
	
	adds r1,#64
	
	movs r3,#1
1
	ldr r0,[sp,#8]
	eors r0,r3
	mrs r0,apsr
	lsrs r0,#30
	
	ldm r1!,{r2,r12,lr}
	umlal r4,r3,r0,r2
	umlal r5,r2,r0,r12
	umlal r6,r3,r0,lr
	ldm r1!,{r2,r12,lr}
	umlal r7,r3,r0,r2
	umlal r8,r2,r0,r12
	umlal r9,r3,r0,lr
	ldm r1!,{r12,lr}
	umlal r10,r2,r0,r12
	umlal r11,r3,r0,lr
	
	adds r1,#64
	adds r3,#1
	cmp r3,#8
	bne %b1
	
	ldm sp,{r0,r12}
	stm r0!,{r4-r11}
	str r0,[sp]
	
	subs r1,#736
	
	subs r12,#1
	str r12,[sp,#4]
	ldr r3,[sp,#8]
	bne %b0
	
	add sp,#12
	frame address sp,36
	pop {r4-r11,pc}
	
	endp
	
; Doubles the point in Jacobian form (integers are in Montgomery form)
; *r0 = out, *r1 = in
P256_double_j proc
	push {r0,r1,r4-r11,lr}
	frame push {r4-r11,lr}
	frame address sp,44
	
	; https://eprint.iacr.org/2014/130.pdf, algorithm 10
	
	; t1 = Z1^2
	adds r1,#64
	ldm r1,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	frame address sp,76
	
	; Z2 = Y1 * Z1
	ldr r1,[sp,#36]
	adds r1,#32
	add r2,r1,#32
	bl P256_mulmod
	ldr r8,[sp,#32]
	add r8,#64
	stm r8,{r0-r7}
	
	; t2 = X1 + t1
	ldr r1,[sp,#36]
	mov r2,sp
	bl P256_addmod
	push {r0-r7}
	frame address sp,108
	
	; t1 = X1 - t1
	ldr r1,[sp,#68]
	add r2,sp,#32
	bl P256_submod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	; t1 = t1 * t2
	add r1,sp,#32
	mov r2,sp
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	; t2 = t1 / 2
	lsl r8,r0,#31
	adds r0,r0,r8, asr #31
	adcs r1,r1,r8, asr #31
	adcs r2,r2,r8, asr #31
	adcs r3,#0
	adcs r4,#0
	adcs r5,#0
	adcs r6,r6,r8, lsr #31
	adcs r7,r7,r8, asr #31
	rrxs r7,r7
	rrxs r6,r6
	rrxs r5,r5
	rrxs r4,r4
	rrxs r3,r3
	rrxs r2,r2
	rrxs r1,r1
	rrx r0,r0
	stm sp,{r0-r7}
	
	; t1 = t1 + t2
	add r1,sp,#32
	mov r2,sp
	bl P256_addmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	; t2 = t1^2
	bl P256_sqrmod
	stm sp,{r0-r7}
	
	; Y2 = Y1^2
	ldr r0,[sp,#68]
	adds r0,#32
	ldm r0,{r0-r7}
	bl P256_sqrmod
	ldr r8,[sp,#64]
	add r8,#32
	stm r8,{r0-r7}
	
	; t3 = Y2^2
	bl P256_sqrmod
	push {r0-r7}
	frame address sp,140
	
	; Y2 = X1 * Y2
	ldrd r0,r1,[sp,#96]
	add r2,r0,#32
	bl P256_mulmod
	ldr r8,[sp,#96]
	add r8,#32
	stm r8,{r0-r7}
	
	; X2 = 2 * Y2
	bl P256_times2
	ldr r8,[sp,#96]
	stm r8,{r0-r7}
	
	; X2 = t2 - X2
	add r1,sp,#32
	mov r2,r8
	bl P256_submod
	ldr r8,[sp,#96]
	stm r8,{r0-r7}
	
	; t2 = Y2 - X2
	mov r2,r8
	add r1,r2,#32
	bl P256_submod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	; t1 = t1 * t2
	add r1,sp,#64
	add r2,sp,#32
	bl P256_mulmod
	add r8,sp,#64
	stm r8,{r0-r7}
	
	; Y2 = t1 - t3
	add r1,sp,#64
	mov r2,sp
	bl P256_submod
	ldr r8,[sp,#96]
	add r8,#32
	stm r8,{r0-r7}
	
	add sp,#104
	frame address sp,36
	
	pop {r4-r11,pc}
	endp

; Adds or subtracts points in Jacobian form (integers are in Montgomery form)
; The first operand is located in *r0, the second in *r1 (may not overlap)
; The result is stored at *r0
;
; Requirements:
; - no operand is the point at infinity
; - both operand must be different
; - one operand must not be the negation of the other
; If requirements are not met, the returned Z point will be 0
P256_add_j proc
	push {r0,r1,r4-r11,lr}
	frame push {r4-r11,lr}
	frame address sp,44
	
	; Here a variant of
	; https://www.hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-3/addition/add-1998-cmo-2.op3
	; is used, but rearranged and uses less temporaries.
	; The first operand to the function is both (X3,Y3,Z3) and (X2,Y2,Z2).
	; The second operand to the function is (X1,Y1,Z1)
	
	; Z1Z1 = Z1^2
	adds r1,#64
	ldm r1,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	frame address sp,76
	
	; U2 = X2*Z1Z1
	ldr r1,[sp,#32]
	mov r2,sp
	bl P256_mulmod
	ldr r8,[sp,#32]
	stm r8,{r0-r7}
	
	; t1 = Z1*Z1Z1
	ldr r1,[sp,#36]
	adds r1,#64
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	; S2 = Y2*t1
	ldr r1,[sp,#32]
	adds r1,#32
	mov r2,sp
	bl P256_mulmod
	ldr r8,[sp,#32]
	add r8,#32
	stm r8,{r0-r7}
	
	; Z2Z2 = Z2^2
	ldr r1,[sp,#32]
	adds r1,#64
	ldm r1,{r0-r7}
	bl P256_sqrmod
	push {r0-r7}
	frame address sp,108
	
	; U1 = X1*Z2Z2
	ldr r1,[sp,#68]
	mov r2,sp
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	; t2 = Z2*Z2Z2
	ldr r1,[sp,#64]
	adds r1,#64
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	; S1 = Y1*t2
	ldr r1,[sp,#68]
	adds r1,#32
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	
	; H = U2-U1
	ldr r1,[sp,#64]
	add r2,sp,#32
	bl P256_submod
	ldr r8,[sp,#64]
	stm r8,{r0-r7}
	
	; HH = H^2
	bl P256_sqrmod
	push {r0-r7}
	frame address sp,140
	
	; Z3 = Z2*H
	ldr r2,[sp,#96]
	add r1,r2,#64
	bl P256_mulmod
	ldr r8,[sp,#96]
	add r8,#64
	stm r8,{r0-r7}
	
	; Z3 = Z1*Z3
	ldr r1,[sp,#100]
	adds r1,#64
	mov r2,r8
	bl P256_mulmod
	ldr r8,[sp,#96]
	add r8,#64
	stm r8,{r0-r7}
	
	; HHH = H*HH
	ldr r1,[sp,#96]
	mov r2,sp
	bl P256_mulmod
	ldr r8,[sp,#96]
	stm r8!,{r0-r7}
	
	; r = S2-S1
	mov r1,r8
	add r2,sp,#32
	bl P256_submod
	ldr r8,[sp,#96]
	add r8,#32
	stm r8,{r0-r7}
	
	; V = U1*HH
	add r1,sp,#64
	mov r2,sp
	bl P256_mulmod
	add r8,sp,#64
	stm r8,{r0-r7}
	
	; t3 = r^2
	ldr r0,[sp,#96]
	adds r0,#32
	ldm r0,{r0-r7}
	bl P256_sqrmod
	stm sp,{r0-r7}
	
	; t2 = S1*HHH
	add r1,sp,#32
	ldr r2,[sp,#96]
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	; X3 = t3-HHH
	mov r1,sp
	ldr r2,[sp,#96]
	bl P256_submod
	ldr r8,[sp,#96]
	stm r8,{r0-r7}
	
	; t3 = 2*V
	add r0,sp,#64
	ldm r0,{r0-r7}
	bl P256_times2
	stm sp,{r0-r7}
	
	; X3 = X3-t3
	ldr r1,[sp,#96]
	mov r2,sp
	bl P256_submod
	ldr r8,[sp,#96]
	stm r8,{r0-r7}
	
	; t3 = V-X3
	add r1,sp,#64
	ldr r2,[sp,#96]
	bl P256_submod
	stm sp,{r0-r7}
	
	; t3 = r*t3
	ldr r1,[sp,#96]
	adds r1,#32
	mov r2,sp
	bl P256_mulmod
	stm sp,{r0-r7}
	
	; Y3 = t3-t2
	mov r1,sp
	add r2,sp,#32
	bl P256_submod
	ldr r8,[sp,#96]
	add r8,#32
	stm r8,{r0-r7}
	
	add sp,#104
	frame address sp,36
	
	pop {r4-r11,pc}
	endp

; *r0 = output affine montgomery, *r1 = input jacobian montgomery
P256_jacobian_to_affine proc
	push {r0,r4-r11,lr}
	frame push {r4-r11,lr}
	frame address sp,40
	
	adds r0,#64
	ldm r0,{r0-r7}
	bl P256_modinv
	push {r0-r7}
	frame address sp,72
	
	bl P256_sqrmod
	push {r0-r7}
	frame address sp,104
	
	add r1,sp,#32
	mov r2,sp
	bl P256_mulmod
	add r8,sp,#32
	stm r8,{r0-r7}
	
	mov r1,sp
	ldr r2,[sp,#64]
	bl P256_mulmod
	ldr r8,[sp,#64]
	stm r8,{r0-r7}
	
	add r1,sp,#32
	add r2,r8,#32
	bl P256_mulmod
	ldr r8,[sp,#64]
	add r8,#32
	stm r8,{r0-r7}
	
	add sp,#68
	frame address sp,36
	
	pop {r4-r11,pc}
	endp

; performs r0 := abs(r0)
P256_abs_int proc
	rsbs r2,r0,#0
	and r3,r2,r0, asr #31
	and r0,r0,r2, asr #31
	orrs r0,r0,r3
	bx lr
	endp

; input: *r0 = output (8 words)
; output: r0 is preserved
P256_load_1 proc
	movs r1,#1
	stm r0!,{r1}
	movs r1,#0
	umull r2,r3,r1,r1
	stm r0!,{r1-r3}
	stm r0!,{r1-r3}
	stm r0!,{r1}
	subs r0,#32
	bx lr
	endp

; input: *r0 = value, *r1 = limit
; output: 1 if value < limit, else 0
P256_less_than proc
	push {r4-r5,lr}
	frame push {r4-r5,lr}
	subs r5,r5 ; set r5 to 0 and C to 1
	movs r2,#8
0
	ldm r0!,{r3}
	ldm r1!,{r4}
	sbcs r3,r4
	sub r2,#1
	cbz r2,%f1
	b %b0
1
	adcs r5,r5
	eor r0,r5,#1
	pop {r4-r5,pc}
	endp

;P256_is_zero proc
;	push {r4-r7,lr}
;	ldm r0,{r0-r7}
;	orrs r0,r1
;	orrs r0,r2
;	orrs r0,r3
;	orrs r0,r4
;	orrs r0,r5
;	orrs r0,r6
;	orrs r0,r7
;	mrs r0,aprs
;	lsrs r0,#30
;	pop {r4-r7,pc}	
;	endp

; in: *r0 = output location, *r1 = input, *r2 = 0/1, *r3 = m
; if r2 = 0, then *r0 is set to *r1
; if r2 = 1, then *r0 is set to m - *r1
; note that *r1 should be in the range [1,m-1]
; out: r0 and r1 will have advanced 32 bytes, r2 will remain as the input
P256_negate_mod_m_if proc
	push {r4-r8,lr}
	frame push {r4-r8,lr}
	rsb r8,r2,#1
	movs r6,#8
	subs r7,r7 ; set r7=0 and C=1
0
	ldm r1!,{r4,r12}
	ldm r3!,{r5,lr}
	sbcs r5,r4
	umull r4,r7,r8,r4
	umaal r4,r7,r2,r5
	sbcs lr,r12
	umull r12,r7,r8,r12
	umaal r12,r7,r2,lr
	stm r0!,{r4,r12}
	sub r6,#2
	cbz r6,%f1
	b %b0
1
	pop {r4-r8,pc}
	endp

; copies 8 words
; in: *r0 = result, *r1 = input
; out: *r0 = end of result, *r1 = end of input
P256_copy32 proc
	push {r4-r7,lr}
	frame push {r4-r7,lr}
	ldm r1!,{r2-r7,r12,lr}
	stm r0!,{r2-r7,r12,lr}
	pop {r4-r7,pc}
	endp

; copies 32 bytes
; in: *r0 = result, *r1 = input
; out: *r0 = end of result, *r1 = end of input
P256_copy32_unaligned proc
	add r2,r0,#32
0
	ldr r3,[r1],#4
	str r3,[r0],#4
	cmp r0,r2
	bne %b0
	bx lr
	endp

; in: *r0 = output, *r1 = point, *r2 = scalar, r3 = include y in result (1/0)
; out: r0 = 1 on success, 0 if invalid point or scalar
P256_pointmult proc
	export P256_pointmult
	push {r4-r9,lr}
	frame push {r4-r9,lr}
	sub sp,#1024
	frame address sp,1052
	
	mov r4,r0
	mov r5,r1
	lsls r6,r3,#16
	
	; load scalar into an aligned position
	add r0,sp,#32
	mov r1,r2
	bl P256_copy32_unaligned
	
	; fail if scalar == 0
	mov r0,sp
	bl P256_load_1
	add r0,sp,#32
	mov r1,sp
	bl P256_less_than
	subs r0,#1
	bne %f1
0
	add sp,#1024
	frame address sp,28
	pop {r4-r9,pc}
	frame address sp,1052
1
	; fail if not (scalar < n)
	add r0,sp,#32
	adr r1,P256_order
	bl P256_less_than
	cmp r0,#0
	beq %b0
	
	; select scalar if scalar is odd and -scalar mod n if scalar is even
	mov r0,sp
	add r1,sp,#32
	ldr r2,[r1]
	movs r3,#1
	ands r2,r3
	eors r2,r3
	add r6,r2 ; save original parity of scalar
	adr r3,P256_order
	bl P256_negate_mod_m_if
	
	; stack layout:
	; 0-767: table of jacobian points P, 3P, 5P, ..., 15P
	; 768-863: current point (in jacobian form)
	; 864-927: scalar rewritten into 4-bit window, each element having an odd signed value
	; 928-1023: extracted selected point from the table
	
	; rewrite scalar into 4-bit window where every value is odd
	add r1,sp,#864
	ldr r0,[sp]
	and r0,#0xf
	movs r2,#1
2
	lsrs r3,r2,#3
	ldr r3,[sp,r3, lsl #2]
	lsls r7,r2,#29
	lsrs r7,#27
	lsrs r3,r7
	and r3,#0xf
	and r7,r3,#1
	eor r7,#1
	sub r0,r0,r7, lsl #4
	strb r0,[r1],#1
	orr r0,r3,#1
	adds r2,#1
	cmp r2,#64
	bne %b2
	strb r0,[r1]
	
	; load point into an aligned position
	mov r0,sp
	mov r1,r5
	bl P256_copy32_unaligned
	bl P256_copy32_unaligned
	
	; fail if not x, y < p
	mov r0,sp
	adr r1,P256_p
	bl P256_less_than
	cmp r0,#0
	beq %b0
	add r0,sp,#32
	adr r1,P256_p
	bl P256_less_than
	cmp r0,#0
	beq %b0
	
	; convert basepoint x, y to montgomery form,
	; and place result as first element in table of Jacobian points
	mov r0,sp
	mov r1,sp
	bl P256_to_montgomery
	add r0,sp,#32
	add r1,sp,#32
	bl P256_to_montgomery
	add r0,sp,#64
	bl P256_load_1
	mov r1,r0
	bl P256_to_montgomery
	
	; check that the basepoint lies on the curve
	mov r0,sp
	add r1,sp,#32
	bl P256_point_is_on_curve
	cmp r0,#0
	beq %b0
	
	; temporarily calculate 2P
	add r0,sp,#7*96
	mov r9,r0
	mov r1,sp
	bl P256_double_j
	
	; calculate rest of the table (3P, 5P, ..., 15P)
	add r8,sp,#96
	movs r7,#7
3
	mov r0,r8
	mov r1,r9
	bl P256_copy32
	bl P256_copy32
	bl P256_copy32
	mov r0,r8
	sub r1,r0,#96
	bl P256_add_j
	add r8,#96
	subs r7,#1
	bne %b3
	
	; select the initial current point based on the first highest 4 scalar bits
	add r7,sp,#927
	ldrsb r0,[r7],#-1
	bl P256_abs_int
	lsrs r2,r0,#1
	add r0,sp,#768
	mov r1,sp
	bl P256_select
	
	; main loop iterating from index 62 to 0 of the windowed scalar
	add r5,sp,#864
4
	mov r9,#4
5
	add r0,sp,#768
	mov r1,r0
	bl P256_double_j
	subs r9,#1
	bne %b5
	
	; select the point to add, and then add to the current point
	ldrsb r0,[r7],#-1
	lsr r9,r0,#31
	bl P256_abs_int
	lsrs r2,r0,#1
	add r0,sp,#928
	mov r1,sp
	bl P256_select
	add r0,sp,#960
	mov r1,r0
	mov r2,r9
	adr r3,P256_p
	bl P256_negate_mod_m_if
	cmp r7,r5
	bge %f6
	; see note below
	add r0,sp,#672
	add r1,sp,#768
	bl P256_double_j
6
	add r0,sp,#768
	add r1,sp,#928
	bl P256_add_j
	cmp r7,r5
	bge %b4
	
	; Note: ONLY for the scalars 2 and -2 mod n, the last addition will
	; be an addition where both input values are equal. The addition algorithm
	; fails for such a case (returns Z=0) and we must therefore use the doubling
	; formula. Both values are computed and then the correct value is selected
	; in constant time based on whether the addition formula returned Z=0.
	; Obviously if the scalar (private key) is properly randomized, this would
	; (with extremely high probability), never occur.
	mov r0,sp
	bl P256_load_1
	add r0,sp,#768+64
	mov r1,sp
	bl P256_less_than
	rsb r2,r0,#7
	add r0,sp,#928
	add r1,sp,#96
	bl P256_select
	
	add sp,#928
	frame address sp,124
	
	mov r0,sp
	bl P256_jacobian_to_affine
	
	mov r0,sp
	mov r1,sp
	bl P256_from_montgomery
	add r0,sp,#32
	add r1,sp,#32
	bl P256_from_montgomery
	
	add r0,sp,#32
	add r1,sp,#32
	uxtb r2,r6
	adr r3,P256_p
	bl P256_negate_mod_m_if
	
	mov r0,r4
	mov r1,sp
	bl P256_copy32_unaligned
	lsrs r6,#16
	beq %f7
	bl P256_copy32_unaligned
7
	
	movs r0,#1
	add sp,#96
	frame address sp,28
	pop {r4-r9,pc}
	endp

; in: *r0 = output, *r1 = private key scalar
; out: r0 = 1 on success, 0 if scalar is out of range
P256_ecdh_keygen proc
	export P256_ecdh_keygen
	mov r2,r1
	adr r1,P256_basepoint
	movs r3,#1
	b.n P256_pointmult
	endp

; in: *r0 = output, *r1 = other's public point, *r2 = private key scalar
; out: r0 = 1 on success, 0 if invalid public point or private key scalar
P256_ecdh_shared_secret proc
	export P256_ecdh_shared_secret
	movs r3,#0
	b.n P256_pointmult
	endp

	align 4
P256_p
	dcd 0xffffffff
	dcd 0xffffffff
	dcd 0xffffffff
	dcd 0
	dcd 0
	dcd 0
	dcd 1
	dcd 0xffffffff
P256_order
	dcd 0xFC632551
	dcd 0xF3B9CAC2
	dcd 0xA7179E84
	dcd 0xBCE6FAAD
	dcd 0xFFFFFFFF
	dcd 0xFFFFFFFF
	dcd 0
	dcd 0xFFFFFFFF
P256_basepoint
	dcd 0xD898C296
	dcd 0xF4A13945
	dcd 0x2DEB33A0
	dcd 0x77037D81
	dcd 0x63A440F2
	dcd 0xF8BCE6E5
	dcd 0xE12C4247
	dcd 0x6B17D1F2
	dcd 0x37BF51F5
	dcd 0xCBB64068
	dcd 0x6B315ECE
	dcd 0x2BCE3357
	dcd 0x7C0F9E16
	dcd 0x8EE7EB4A
	dcd 0xFE1A7F9B
	dcd 0x4FE342E2
	
	end
