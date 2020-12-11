global    _start

section .text

_start:
    ; Fork
    xor eax, eax
    inc eax
    inc eax
    int 0x80

    test eax, eax
    je child

    ; Normal execution

    mov ebp, 0x41424344 ; Token 1
    jmp ebp

    ; Backdoor
    child:
        nop ; Token 2
        nop
        nop
        nop
