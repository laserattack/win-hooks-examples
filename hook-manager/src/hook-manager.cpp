#include "hook-manager.h"
#include <stdio.h>
#include <stdlib.h>

HookManager::HookManager(void* hookAddr, void* detourFuncAddr, size_t hookSize)
    : hookAddr(hookAddr), detourFuncAddr(detourFuncAddr), hookSize(hookSize) {}
void* HookManager::getDetourFuncAddr() { return detourFuncAddr; }
void* HookManager::getHookAddr() { return hookAddr; }

void HookManager::hook() {
    if (isHooked) return;
    memcpy(originalBytes, hookAddr, hookSize);
    DWORD oldProtect;
    VirtualProtect(hookAddr, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    uint8_t* hookPtr = (uint8_t*)hookAddr;
    void* hkd = (void*)hooked;
	// Патч
	// movabs r15, адрес_функции
	// jmp r15
    hookPtr[0] = 0x49;
    hookPtr[1] = 0xBF;
    memcpy(hookPtr + 2, &hkd, sizeof(void*));
    hookPtr[10] = 0x41;
    hookPtr[11] = 0xFF;
    hookPtr[12] = 0xE7;
    VirtualProtect(hookAddr, hookSize, oldProtect, &oldProtect);
    isHooked = true;
}

void HookManager::unhook() {
    if (!isHooked) return;
    DWORD oldProtect;
    VirtualProtect((void*)hookAddr, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)hookAddr, originalBytes, hookSize);
    VirtualProtect((void*)hookAddr, hookSize, oldProtect, &oldProtect);
    isHooked = false;
}

HookManager* hookManager = nullptr;

void hooked() {
    // в r15 адрес возврата
    // в r14 rsp каким он был до вызова функции (для передачи аргументов функции через стек)
    asm volatile ( \
        "add $0x30, %rsp\n" \
        "pop %r13\n" \
        "mov %rbp, %r15\n" \
        "add $0x8, %r15\n" \
        "mov (%r15), %r15\n" \
        "mov %rbp, %r14\n" \
        "add $0x10, %r14\n" \
        "push %rax\n" \
        "push %rbx\n" \
        "push %rcx\n" \
        "push %rdx\n" \
        "push %rsi\n" \
        "push %rdi\n" \
        "push %r8\n" \
        "push %r9\n" \
        "push %r10\n" \
        "push %r11\n" \
        "push %r12\n" \
    );
    asm volatile (
        "call *%[detourFuncAddr]\n"
        :
        : [detourFuncAddr] "r" (hookManager->getDetourFuncAddr())
    );
    hookManager->unhook();
    void* hookAddr = hookManager->getHookAddr();
    // не забываем восстановить rsp для передачи аргументов через стек
    asm volatile ( \
        "pop %r12\n" \
        "pop %r11\n" \
        "pop %r10\n" \
        "pop %r9\n" \
        "pop %r8\n" \
        "pop %rdi\n" \
        "pop %rsi\n" \
        "pop %rdx\n" \
        "pop %rcx\n" \
        "pop %rbx\n" \
        "pop %rax\n" \
        "mov %r14, %rsp\n" \
    );
    asm volatile (
        "call *%[hookAddr]\n"
        :
        : [hookAddr] "r" (hookAddr)
    );
    asm volatile ( \
        "push %rax\n" \
        "push %rbx\n" \
        "push %rcx\n" \
        "push %rdx\n" \
        "push %rsi\n" \
        "push %rdi\n" \
        "push %r8\n" \
        "push %r9\n" \
        "push %r10\n" \
        "push %r11\n" \
        "push %r12\n" \
        "push %r13\n" \
        "push %r14\n" \
    );
    hookManager->hook();
    asm volatile ( \
        "pop %r14\n" \
        "pop %r13\n" \
        "pop %r12\n" \
        "pop %r11\n" \
        "pop %r10\n" \
        "pop %r9\n" \
        "pop %r8\n" \
        "pop %rdi\n" \
        "pop %rsi\n" \
        "pop %rdx\n" \
        "pop %rcx\n" \
        "pop %rbx\n" \
        "pop %rax\n" \
        "mov %r13, %rbp\n" \
        "jmp *%r15\n" \
    );
}