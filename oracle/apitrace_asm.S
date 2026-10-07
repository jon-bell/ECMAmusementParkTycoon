/* Entry and exit trampolines of the API trace (apitrace.c), and the embedded signature table.
 *
 * Every traced call goes  game: call [IAT]  ->  thunk_i: mov [at_cur_id], i; jmp at_pre_entry.
 * at_pre_entry switches to a private stack before running any C code, so the game's stack below
 * its esp is left exactly as an untraced call leaves it; at_pre may replace the return address
 * with at_post_entry. The callee returns there; at_post_entry switches stacks again, at_post
 * writes the original return address back into the (now stale) slot and returns it, and the
 * trampoline jumps to it. Registers and flags are restored as the callee left them.
 * Single-threaded by construction (the pinned game calls its imports from one thread only;
 * apitrace.c counts and reports any other thread). */
    .intel_syntax noprefix
    .data
    .globl _at_game_esp, _at_priv_top, _at_target, _at_cur_id
    .balign 4
_at_game_esp: .long 0
_at_priv_top: .long 0
_at_target:   .long 0
_at_cur_id:   .long 0

    .text
    .globl _at_pre_entry, _at_post_entry, _at_call_priv
_at_pre_entry:
    mov [_at_game_esp], esp
    mov esp, [_at_priv_top]
    pushfd
    pushad
    cld
    mov eax, esp                    /* regs: pushad block, eflags above it */
    push eax
    push dword ptr [_at_game_esp]
    push dword ptr [_at_cur_id]
    call _at_pre                    /* -> eax: where to jump (the original function) */
    add esp, 12
    mov [_at_target], eax
    popad
    popfd
    mov esp, [_at_game_esp]
    jmp dword ptr [_at_target]

_at_post_entry:
    mov [_at_game_esp], esp
    mov esp, [_at_priv_top]
    pushfd
    pushad
    cld
    mov eax, esp
    push eax
    push dword ptr [_at_game_esp]
    call _at_post                   /* -> eax: the game's return address */
    add esp, 8
    mov [_at_target], eax
    popad
    popfd
    mov esp, [_at_game_esp]
    jmp dword ptr [_at_target]

/* void __cdecl at_call_priv(void (__cdecl *fn)(void *), void *arg): run fn(arg) on the private
 * stack (callback records are rendered there, not below the OS's frames) */
_at_call_priv:
    mov eax, [esp+4]
    mov ecx, [esp+8]
    mov edx, esp
    mov esp, [_at_priv_top]
    push edx
    push ecx
    call eax
    add esp, 4
    pop esp
    ret

    .section .rdata,"dr"
    .globl _apisig_txt
_apisig_txt:
    .incbin "apisig.txt"
    .byte 0
