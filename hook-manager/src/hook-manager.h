#ifndef HOOK_MANAGER_H
#define HOOK_MANAGER_H

#include <Windows.h>
#include <stdint.h>

class HookManager {
private:
    void* hookAddr; // Адрес хукаемой функции
    void* payloadFuncAddr; // Функция, реализующая полезную нагрузку вместе с вызовом хукаемой функции
    uint8_t originalBytes[13] = { 0 };
    bool isHooked = false;
    
public:
    HookManager(void* hookAddr, void* payloadFuncAddr);
    void* getPayloadFuncAddr();
    void* getHookAddr();
    void hook();
	void hook(void* detourFunc);
    void unhook();
};
extern HookManager* hookManager;
extern void hooked();

extern HANDLE hookCreateFileA(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);
#endif