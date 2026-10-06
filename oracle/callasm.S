/* void __cdecl call_asm(uint32_t target, regs_t *r)
 * Calls a game routine with eax..ebp taken from *r and stores eax..ebp and eflags back.
 * regs_t layout (pushad order): edi 0, esi 4, ebp 8, esp 12, ebx 16, edx 20, ecx 24, eax 28, eflags 32 */
    .intel_syntax noprefix
    .text
    .globl _call_asm
_call_asm:
    push ebp
    push ebx
    push esi
    push edi
    mov eax, [esp+20]          /* target */
    mov ecx, [esp+24]          /* regs */
    push ecx
    push eax
    mov eax, [ecx+28]
    mov ebx, [ecx+16]
    mov edx, [ecx+20]
    mov esi, [ecx+4]
    mov edi, [ecx+0]
    mov ebp, [ecx+8]
    mov ecx, [ecx+24]
    call dword ptr [esp]
    pushfd
    push ecx
    mov ecx, [esp+12]          /* regs (stack: ecx, flags, target, regs) */
    mov [ecx+28], eax
    mov [ecx+16], ebx
    mov [ecx+20], edx
    mov [ecx+4], esi
    mov [ecx+0], edi
    mov [ecx+8], ebp
    pop eax
    mov [ecx+24], eax
    pop eax
    mov [ecx+32], eax
    add esp, 8
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
