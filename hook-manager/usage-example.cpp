// g++ -m64 usage-example.cpp src/hook-manager.cpp && a.exe && del a.exe

#include "src/hook-manager.h"
#include <Windows.h>
#include <stdio.h>

void testHookCloseHandle();
void testHookCreateFileA();
void payload();

int main() {
	printf("testHookCloseHandle\n");
    testHookCloseHandle();
	printf("testHookCreateFileA\n");
    testHookCreateFileA();
    return 0;
}

void testHookCreateFileA() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");

    void* detourFuncAddr = (void*)payload;
    void* hookAddr = (void*)GetProcAddress(hKernel32, "CreateFileA");

    hookManager = new HookManager(hookAddr, detourFuncAddr);
    hookManager->hook();

	for (int i = 0; i < 10; ++i) {
		HANDLE hFile = CreateFileA(
			"testfile.tmp",
			GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		CloseHandle(hFile);
		DeleteFileA("testfile.tmp");
	}

    hookManager->unhook();
    FreeLibrary(hKernel32);
    printf("Good job!\n");
}

void testHookCloseHandle() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");

    void* detourFuncAddr = (void*)payload;
    void* hookAddr = (void*)GetProcAddress(hKernel32, "CloseHandle");

    hookManager = new HookManager(hookAddr, detourFuncAddr);
    hookManager->hook();

	for (int i = 0; i < 5; ++i) {
		HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (!CloseHandle(hEvent)) exit(1);
		if (CloseHandle(hEvent)) exit(1);
	}

    hookManager->unhook();
    FreeLibrary(hKernel32);
    printf("Good job!\n");
}

void payload() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d.%03d] Hooked\n", 
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}