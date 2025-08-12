// g++ -m64 usage-example.cpp src/hook-manager.cpp && a.exe && del a.exe

#include "src/hook-manager.h"
#include <Windows.h>
#include <stdio.h>

void testHookCloseHandle();
void testHookCreateFileA();
void testConcreteHookCreateFileA();
void payload();

int main() {
	// Первый режим работы
	printf("	testHookCloseHandle\n");
    testHookCloseHandle();
	printf("	testHookCreateFileA\n");
    testHookCreateFileA();
	// Второй режим работы (хуки с перехватом аргументов)
	printf("	testConcreteHookCreateFileA\n");
	testConcreteHookCreateFileA();
    return 0;
}

void testConcreteHookCreateFileA() {
	HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
	void* hookAddr = (void*)GetProcAddress(hKernel32, "CreateFileA");
	
	// Не передаю адрес функции, исполняющей полезную нагрузку
	// Значит в hook надо будет передать адрес функции, которой хукать
	// такие функции должны иметь сигнатуру хукаемых функций и прописываться
	// вниз файла hook-manager.cpp и как extern в hook-manager.hEvent
	// хуки такого вида позволяют получить доступ к аргументам вызываемых функций
	hookManager = new HookManager(hookAddr, NULL);
	hookManager->hook((void*)hookCreateFileA);
	
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
	
	//
	hookManager->unhook();
	delete hookManager;
	FreeLibrary(hKernel32);
	printf("Good job!\n");
}

void testHookCreateFileA() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");

    void* payloadFuncAddr = (void*)payload;
    void* hookAddr = (void*)GetProcAddress(hKernel32, "CreateFileA");

    hookManager = new HookManager(hookAddr, payloadFuncAddr);
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
	delete hookManager;
    FreeLibrary(hKernel32);
    printf("Good job!\n");
}

void testHookCloseHandle() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");

    void* payloadFuncAddr = (void*)payload;
    void* hookAddr = (void*)GetProcAddress(hKernel32, "CloseHandle");

    hookManager = new HookManager(hookAddr, payloadFuncAddr);
    hookManager->hook();

	for (int i = 0; i < 5; ++i) {
		HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (!CloseHandle(hEvent)) exit(1);
		if (CloseHandle(hEvent)) exit(1);
	}

    hookManager->unhook();
	delete hookManager;
    FreeLibrary(hKernel32);
    printf("Good job!\n");
}

void payload() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d.%03d] Hooked\n", 
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}