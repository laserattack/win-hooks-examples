#ifndef HOOK_MANAGER_H
#define HOOK_MANAGER_H

#include <Windows.h>
#include <stdint.h>

class HookManager {
private:
    void* hookAddr;
    void* detourFuncAddr;
    size_t hookSize;
    uint8_t originalBytes[100] = { 0 };
    bool isHooked = false;
    
public:
    HookManager(void* hookAddr, void* detourFuncAddr, size_t hookSize);
    void* getDetourFuncAddr();
    void* getHookAddr();
    void hook();
    void unhook();
};
extern HookManager* hookManager;
extern void hooked();
#endif