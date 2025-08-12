#include "hook-manager.h"
#include <stdio.h>
#include <stdlib.h>

HookManager::HookManager(void* hookAddr, void* detourFuncAddr)
    : hookAddr(hookAddr), detourFuncAddr(detourFuncAddr) {}
void* HookManager::getDetourFuncAddr() { return detourFuncAddr; }
void* HookManager::getHookAddr() { return hookAddr; }

// Установка хука
void HookManager::hook() {
    if (isHooked) return;
	// Сохранение оригинальных байт
    memcpy(originalBytes, hookAddr, 13);
	// Выдача разрешения на запись на странице памяти с целевой функцией
    DWORD oldProtect;
    VirtualProtect(hookAddr, 13, PAGE_EXECUTE_READWRITE, &oldProtect);
	// ------------------------
    void* hkd = (void*)hooked;
	// Патч
	// mov r11, АДРЕС_ФУНКЦИИ
	// jmp r11
	uint8_t patch[13] = { 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3 };
    memcpy(patch + 2, &hkd, sizeof(void*));
	memcpy(hookAddr, patch, 13);
	// ------------------------
	// Восстановление разрешений
    VirtualProtect(hookAddr, 13, oldProtect, &oldProtect);
    isHooked = true;
}

// Снятие хука
void HookManager::unhook() {
    if (!isHooked) return;
    DWORD oldProtect;
    VirtualProtect((void*)hookAddr, 13, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)hookAddr, originalBytes, 13);
    VirtualProtect((void*)hookAddr, 13, oldProtect, &oldProtect);
    isHooked = false;
}

HookManager* hookManager = nullptr;

// Функция обертка, сохраняющая состояние стека чтобы 
// корректо вызвать оригинальную функцию
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