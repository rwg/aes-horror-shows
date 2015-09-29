; aes128-encrypt.s
; 
; single block AES-128 encryption for microcorruption.com's emulated MSP430
; 
; Richard Godbee <richard@godbee.net> / 2014-07-16

; ########## main ##########

.section .init9, "ax", @progbits
.global main

main:
    sub #54, r1                     ; 0(r1) - 17(r1): plaintext + '\0'
                                    ; 18(r1) - 35(r1): key + '\0'
                                    ; 36(r1) - 53(r1): ciphertext (no '\0')

    ; get plaintext

    mov #c__plaintext_prompt, r15
    call #print_string

    mov r1, r15
    call #get_16

    ; get key

    mov #c__key_prompt, r15
    call #print_string

    mov r1, r15
    add #18, r15
    call #get_16

    ; print blank line

    mov #0x0a, r15                  ; LF
    call #print_char

    ; encryption time!

    mov r1, r15                     ; &plaintext
    mov r1, r14
    add #18, r14                    ; &key
    mov r1, r13
    add #36, r13                    ; &ciphertext
    call #aes128_encrypt

    add #54, r1

    ; main falls through to __stop_progExec__

; ########## functions ##########

.section .text

; ===== aes128_encrypt =====
; r15: &plaintext (16 bytes)
; r14: &key (16 bytes)
; r13: &ciphertext (16 bytes)

aes128_encrypt:
    push r4                         ; clobbered
    push r5                         ; clobbered
    push r6                         ; clobbered

    push r15                        ; 804(r1): &plaintext
    push r14                        ; 802(r1): &key
    push r13                        ; 800(r1): &ciphertext

    sub #800, r1                    ; 0(r1): 50 16-byte chunks

    ; round 0 ("input") -- just XOR the plaintext with the key

    mov r1, r13
    call #xor_16

    ; rounds 1-10

    mov #1, r5                      ; r5: round number
    mov r1, r4                      ; r4: &(current position in state)

1$:
    mov r4, r15
    mov r4, r14
    add #16, r14
    call #aes_subbytes

    mov r4, r15
    add #16, r15
    mov r4, r14
    add #32, r14
    call #aes_shiftrows

    mov r4, r15
    add #32, r15
    mov r4, r14
    add #48, r14

    cmp #10, r5
    jeq 2$

    ; rounds 1-9
    call #aes_mixcolumns
    jmp 3$

2$:
    ; round 10
    call #copy_16

3$:
    mov r4, r15
    sub #16, r15
    mov r4, r14
    add #64, r14
    mov r5, r13

    cmp #1, r5
    jne 5$

    mov 802(r1), r15                ; for round 1, src is &key

5$:
    call #aes128_key_expansion

    mov r4, r15
    add #48, r15
    mov r4, r14
    add #64, r14
    mov r4, r13
    add #80, r13

    cmp #10, r5
    jne 4$

    mov 800(r1), r13                ; for round 10, output goes to ciphertext

4$:
    call #xor_16

    add #80, r4

    inc r5
    cmp #11, r5
    jne 1$

    ; ---------- printing the state below this line ----------

    ; print plaintext

    mov #c__plaintext, r15
    call #print_string

    mov 804(r1), r15
    mov #16, r14
    call #print_hex_buffer

    mov #0x0a, r15                  ; LF
    call #print_char

    ; print key

    mov #c__key, r15
    call #print_string

    mov 802(r1), r15
    mov #16, r14
    call #print_hex_buffer

    mov #0x0a, r15                  ; LF
    call #print_char

    ; print ciphertext

    mov #c__ciphertext, r15
    call #print_string

    mov 800(r1), r15
    mov #16, r14
    call #print_hex_buffer

    mov #0x0a, r15                  ; LF
    call #print_char

    ; print blank line

    mov #0x0a, r15                  ; LF
    call #print_char

    ; print dashed line

    call #print_dashed_line

    ; print header lines

    mov #c__header_1, r15
    call #print_string

    mov #c__header_2, r15
    call #print_string

    ; print dashed line

    call #print_dashed_line

    ; print state from each round

    mov #0, r5                      ; r5: round number (0 ["input"], 1-10, 11
                                    ;     ["output"])

100$:
    mov #0, r6                      ; r6: line number within row (0-3)

    cmp #1, r5                      ; if it's not round 1, skip setting r4
    jne 101$                        ; (r4 is garbage at the end of round 0)

    mov r1, r4                      ; r4: &(current position in state)

101$:
    mov #0x7c, r15                  ; "|"
    call #print_char

    ; round number (on line 1 only)
    cmp #1, r6
    jeq 102$

    mov #0x20, r15                  ; " " (space)
    mov #6, r14
    call #print_char_repeatedly

    jmp 103$

102$:
    mov r5, r15
    call #aes128_print_round_number

103$:
    mov #0x7c, r15                  ; "|"
    call #print_char

    ; start of round
    tst r5
    jz 151$                          ; round 0

    cmp #11, r5
    jeq 152$                         ; round 11

    mov r4, r15

    jmp 153$

151$:
    mov 804(r1), r15                ; &plaintext
    add r6, r15                     ; + line number
    jmp 153$

152$:
    mov 800(r1), r15                ; &ciphertext
    add r6, r15                     ; + line number

153$:
    call #print_every_fourth_byte

    add #16, r4

    mov #0x7c, r15                  ; "|"
    call #print_char

    ; after subbytes
    tst r5
    jz 169$                         ; round 0 doesn't do subbytes

    cmp #11, r5
    jeq 169$                        ; round 11 doesn't, either

    mov r4, r15
    call #print_every_fourth_byte

    jmp 170$

169$:
    mov #0x20, r15                  ; " " (space)
    mov #11, r14
    call #print_char_repeatedly

170$:
    add #16, r4

    mov #0x7c, r15                  ; "|"
    call #print_char

    ; after shiftrows
    tst r5
    jz 179$                         ; round 0 doesn't do shiftrows

    cmp #11, r5
    jeq 179$                        ; round 11 doesn't, either

    mov r4, r15
    call #print_every_fourth_byte

    jmp 180$

179$:
    mov #0x20, r15                  ; " " (space)
    mov #11, r14
    call #print_char_repeatedly

180$:
    add #16, r4

    mov #0x7c, r15                  ; "|"
    call #print_char

    ; after mixcolumns
    tst r5
    jz 189$                         ; round 0 doesn't do mixcolumns

    cmp #10, r5
    jge 189$                        ; rounds 10 and 11 don't, either

    mov r4, r15
    call #print_every_fourth_byte

    jmp 190$

189$:
    mov #0x20, r15                  ; " " (space)
    mov #11, r14
    call #print_char_repeatedly

190$:
    add #16, r4

    mov #0x7c, r15                  ; "|"
    call #print_char

    ; round key value
    cmp #11, r5
    jeq 199$                        ; round 11 doesn't have a round key value

    mov r4, r15

    tst r5
    jne 191$

    mov 802(r1), r15
    add r6, r15

191$:
    call #print_every_fourth_byte
    jmp 200$

199$:
    mov #0x20, r15                  ; " " (space)
    mov #11, r14
    call #print_char_repeatedly

200$:
    mov #0x7c, r15                  ; "|"
    call #print_char

    mov #0x0a, r15                  ; LF
    call #print_char

    sub #63, r4                     ; move the state pointer to the next byte
                                    ; at the start of this round

    inc r6
    cmp #4, r6
    jl 101$

    call #print_dashed_line

    add #76, r4                     ; increment r4 by one row (5*16 bytes)
                                    ; minus the four byte offset

    inc r5

    cmp #12, r5
    jl 100$

    ; end

    add #800, r1

    pop r13
    pop r14
    pop r15

    pop r6
    pop r5
    pop r4

    ret

; ===== print_every_fourth_byte =====
; r15: &src

print_every_fourth_byte:
    push r4                         ; clobbered
    push r5                         ; clobbered

    mov r15, r4                     ; r4: &(current position)

    mov r15, r5
    add #16, r5                     ; r5: &end
    jmp 2$

1$:
    mov #0x20, r15                  ; " " (space)
    call #print_char

2$:
    mov.b @r4, r15
    call #print_hex_byte

    add #4, r4
    cmp r4, r5
    jne 1$

    pop r5
    pop r4

    ret

; ===== aes128_key_expansion =====
; r15: &src
; r14: &dest
; r13: round number (1-10)

aes128_key_expansion:
    push r5                         ; clobbered
    push r4                         ; clobbered

    dec r13
    add #c__aes128_rcon, r13
    mov.b @r13, r4                  ; r4: rcon(round number)

    mov #0, r12                     ; r12: current byte number (0-15)
    mov r14, r11                    ; r11: &(current dest)

1$:
    cmp #4, r12
    jl 2$

    ; last 12 bytes

    mov r11, r5
    sub #4, r5
    mov.b @r5, r5                   ; r5: temp (appropriate byte of w[i-1])

    jmp 3$

2$:
    ; first 4 bytes

    mov r12, r5
    inc r5                          ; r5: (byte number) + 1

    cmp #4, r5
    jne 4$

    mov #0, r5                      ; r5: ((byte number) + 1) mod 4

4$:
    add r15, r5
    add #12, r5
    mov.b @r5, r5                   ; r5: rot(temp)

    add #c__aes_sbox, r5
    mov.b @r5, r5                   ; r5: sbox(rot(temp))

    tst r12                         ; the lower three bytes of the round
    jnz 3$                          ; constants are zeroes, so only XOR the
                                    ; first byte

    xor.b r4, r5                    ; r5: sbox(rot(temp)) XOR rcon(round number)

3$:
    mov r15, r13
    add r12, r13
    mov.b @r13, @r11                ; r13: appropriate byte of &w[i-Nk]

    xor.b r5, @r11

    inc r11
    inc r12

    cmp #16, r12
    jne 1$

    pop r4
    pop r5

    ret

; ===== aes128_print_round_number =====
; r15: round number (0-11)

aes128_print_round_number:
    tst r15
    jz 100$                         ; (round number) == 0 ("input")
    jl 9999$                        ; ERROR: (round number) < 0

    cmp #11, r15
    jeq 200$                        ; (round number) == 11 ("output")
    jge 9999$                       ; ERROR: (round number) >= 11

    ; numeric round number

    push r4                         ; clobbered

    mov r15, r4                     ; r4: round number

    mov #0x20, r15                  ; " " (space)
    mov #2, r14
    call #print_char_repeatedly

    cmp #10, r4
    jge 2$                          ; (round number) >= 10?

    mov #0x20, r15                  ; " " (space)
    call #print_char

1$:
    ; one's digit

    add #c__hex_digits, r4
    mov.b @r4, r15
    call #print_char

    mov #0x20, r15                  ; " " (space)
    mov #2, r14
    call #print_char_repeatedly

    pop r4

    ret

2$:
    ; ten's digit

    mov #0x31, r15                  ; "1"
    call #print_char

    sub #10, r4

    jmp 1$

100$:
    ; "input" round

    mov #c__input_round_number, r15
    call #print_string

    ret

200$:
    ; "output" round

    mov #c__output_round_number, r15
    call #print_string

    ret

9999$:
    ; error of some sort -- print six question marks and bail

    mov #0x3f, r15                  ; "?"
    mov #6, r14
    call #print_char_repeatedly

    ret

; ===== aes_subbytes =====
; r15: &src
; r14: &dest

aes_subbytes:
    mov #16, r13                    ; r13: bytes left

1$:
    mov.b @r15+, r12
    add #c__aes_sbox, r12
    mov.b @r12, @r14
    inc r14

    dec r13
    jnz 1$

    ret

; ===== aes_shiftrows =====
; r15: &src
; r14: &dest

; +-----------+    +-----------+
; | 0  4  8 12|    | 0  4  8 12|
; | 1  5  9 13| -> | 5  9 13  1|
; | 2  6 10 14|    |10 14  2  6|
; | 3  7 11 15|    |15  3  7 11|
; +-----------+    +-----------+

aes_shiftrows:
    mov.b @r15+,  0(r14)
    mov.b @r15+, 13(r14)
    mov.b @r15+, 10(r14)
    mov.b @r15+,  7(r14)

    mov.b @r15+,  4(r14)
    mov.b @r15+,  1(r14)
    mov.b @r15+, 14(r14)
    mov.b @r15+, 11(r14)

    mov.b @r15+,  8(r14)
    mov.b @r15+,  5(r14)
    mov.b @r15+,  2(r14)
    mov.b @r15+, 15(r14)

    mov.b @r15+, 12(r14)
    mov.b @r15+,  9(r14)
    mov.b @r15+,  6(r14)
    mov.b @r15+,  3(r14)

    ret

; ===== aes_mixcolumns =====
; r15: &src
; r14: &dest

aes_mixcolumns:
    mov r15, r11
    add #16, r11                    ; r11: &end

1$:
    ; first byte of column

    mov.b 0(r15), r12
    add #c__GF_multiply_2, r12
    mov.b @r12, r13

    mov.b 1(r15), r12
    add #c__GF_multiply_3, r12
    xor.b @r12, r13

    xor.b 2(r15), r13

    xor.b 3(r15), r13

    mov.b r13, 0(r14)

    ; second byte of column

    mov.b 0(r15), r13

    mov.b 1(r15), r12
    add #c__GF_multiply_2, r12
    xor.b @r12, r13

    mov.b 2(r15), r12
    add #c__GF_multiply_3, r12
    xor.b @r12, r13

    xor.b 3(r15), r13

    mov.b r13, 1(r14)

    ; third byte of column

    mov.b 0(r15), r13

    xor.b 1(r15), r13

    mov.b 2(r15), r12
    add #c__GF_multiply_2, r12
    xor.b @r12, r13

    mov.b 3(r15), r12
    add #c__GF_multiply_3, r12
    xor.b @r12, r13

    mov.b r13, 2(r14)

    ; fourth byte of column

    mov.b 0(r15), r12
    add #c__GF_multiply_3, r12
    mov.b @r12, r13

    xor.b 1(r15), r13

    xor.b 2(r15), r13

    mov.b 3(r15), r12
    add #c__GF_multiply_2, r12
    xor.b @r12, r13

    mov.b r13, 3(r14)

    add #4, r14
    add #4, r15

    cmp r15, r11
    jne 1$

    ret

; ===== xor_16 =====
; r15: &src1
; r14: &src2
; r13: &dest

xor_16:
    mov #16, r12                    ; r12: bytes remaining to XOR

1$:
    mov @r15+, @r13
    xor @r14+, @r13
    incd r13

    decd r12
    jnz 1$

    ret

; ===== copy_16 =====
; r15: &src
; r14: &dest

copy_16:
    mov #16, r13                    ; r13: bytes remaining to copy

1$:
    mov @r15+, @r14
    incd r14

    decd r13
    jnz 1$

    ret

; ===== get_16 =====
; r15: &dest

get_16:
    push #16
    push r15
    sub #6, r1

    mov #0x8200, r2                 ; INT 0x02 = gets
    call #0x10

    add #10, r1

    ret

; ===== print_char =====
; r15: char to print

print_char:
    push r15
    sub #6, r1

    mov #0x8000, r2                 ; INT 0x00 = putchar
    call #0x10

    add #8, r1

    ret

; ===== print_char_repeatedly =====
; r15: char to print
; r14: count

print_char_repeatedly:
    push r4                         ; clobbered
    push r5                         ; clobbered

    mov r15, r4                     ; r4: char to print
    mov r14, r5                     ; r5: bytes remaining

1$:
    tst r5
    jz 2$

    mov r4, r15
    call #print_char

    dec r5
    jmp 1$

2$:
    pop r5
    pop r4

    ret

; ===== print_hex_buffer =====
; r15: &buffer
; r14: length

print_hex_buffer:
    push r4                         ; clobbered
    push r5                         ; clobbered

    mov r15, r4                     ; r4: &(current position)
    mov r14, r5                     ; r5: bytes remaining

1$:
    tst r5
    jz 2$

    mov.b @r4+, r15                 ; r15: byte to print
    call #print_hex_byte

    dec r5
    jmp 1$

2$:
    pop r5
    pop r4

    ret

; ===== print_hex_byte =====
; r15: byte to print

print_hex_byte:
    ; high nibble

    push r15

    and #0xf0, r15
    rra r15
    rra r15
    rra r15
    rra r15

    add #c__hex_digits, r15
    mov.b @r15, r15
    call #print_char

    ; low nibble

    pop r15

    and #0x0f, r15
    
    add #c__hex_digits, r15
    mov.b @r15, r15
    call #print_char

    ret

; ===== print_string =====
; r15: address of zero-terminated string

print_string:
    push r4                        ; clobbered

    mov r15, r4                    ; r4: current position

1$:
    mov.b @r4+, r15                ; r15: char to print

    tst r15
    jz 2$

    call #print_char

    jmp 1$

2$:
    pop r4

    ret

; ===== print_dashed_line =====

print_dashed_line:
    mov #c__dashed_line, r15
    call #print_string

    ret

; ########## constants ##########

.section .rodata

c__hex_digits:
    .ascii "0123456789abcdef"

c__GF_multiply_2:
    .byte 0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e
    .byte 0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e
    .byte 0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e
    .byte 0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e
    .byte 0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e
    .byte 0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e
    .byte 0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e
    .byte 0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e
    .byte 0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e
    .byte 0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e
    .byte 0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae
    .byte 0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe
    .byte 0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce
    .byte 0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde
    .byte 0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee
    .byte 0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe
    .byte 0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15
    .byte 0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05
    .byte 0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35
    .byte 0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25
    .byte 0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55
    .byte 0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45
    .byte 0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75
    .byte 0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65
    .byte 0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95
    .byte 0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85
    .byte 0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5
    .byte 0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5
    .byte 0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5
    .byte 0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5
    .byte 0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5
    .byte 0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5

c__GF_multiply_3:
    .byte 0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09
    .byte 0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11
    .byte 0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39
    .byte 0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21
    .byte 0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69
    .byte 0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71
    .byte 0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59
    .byte 0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41
    .byte 0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9
    .byte 0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1
    .byte 0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9
    .byte 0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1
    .byte 0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9
    .byte 0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1
    .byte 0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99
    .byte 0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81
    .byte 0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92
    .byte 0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a
    .byte 0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2
    .byte 0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba
    .byte 0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2
    .byte 0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea
    .byte 0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2
    .byte 0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda
    .byte 0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52
    .byte 0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a
    .byte 0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62
    .byte 0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a
    .byte 0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32
    .byte 0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a
    .byte 0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02
    .byte 0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a

c__aes_sbox:
    .byte 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5
    .byte 0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
    .byte 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0
    .byte 0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0
    .byte 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc
    .byte 0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15
    .byte 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a
    .byte 0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75
    .byte 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0
    .byte 0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84
    .byte 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b
    .byte 0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf
    .byte 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85
    .byte 0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8
    .byte 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5
    .byte 0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2
    .byte 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17
    .byte 0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73
    .byte 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88
    .byte 0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb
    .byte 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c
    .byte 0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79
    .byte 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9
    .byte 0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08
    .byte 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6
    .byte 0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a
    .byte 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e
    .byte 0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e
    .byte 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94
    .byte 0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf
    .byte 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68
    .byte 0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16

c__aes128_rcon:
    .byte 1,2,4,8,16,32,64,128,27,54

c__plaintext_prompt:
    .asciz "plaintext (16 bytes)?\n"

c__key_prompt:
    .asciz "key (16 bytes)?\n"

c__plaintext:
    .asciz " Plaintext: "

c__key:
    .asciz "       Key: "

c__ciphertext:
    .asciz "Ciphertext: "

c__dashed_line:
    .ascii "+"
    .ascii "------"
    .ascii "+"
    .ascii "-----------"
    .ascii "+"
    .ascii "-----------"
    .ascii "+"
    .ascii "-----------"
    .ascii "+"
    .ascii "-----------"
    .ascii "+"
    .ascii "-----------"
    .ascii "+"
    .asciz "\n"

c__header_1:
    .ascii "|"
    .ascii " Round"
    .ascii "|"
    .ascii "  Start of "
    .ascii "|"
    .ascii "    After  "
    .ascii "|"
    .ascii "    After  "
    .ascii "|"
    .ascii "    After  "
    .ascii "|"
    .ascii " Round Key "
    .ascii "|"
    .asciz "\n"

c__header_2:
    .ascii "|"
    .ascii "Number"
    .ascii "|"
    .ascii "   Round   "
    .ascii "|"
    .ascii "  SubBytes "
    .ascii "|"
    .ascii " ShiftRows "
    .ascii "|"
    .ascii " MixColumns"
    .ascii "|"
    .ascii "   Value   "
    .ascii "|"
    .asciz "\n"

c__input_round_number:
    .asciz " input"

c__output_round_number:
    .asciz "output"

