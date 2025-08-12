// gcc64 hook-x64.c && a.exe && del a.exe
// x64 хук фукнции CreateFileA

#include <stdio.h>
#include <Windows.h>

// Адрес хукаемой функции
FARPROC hookedAddress;
// Буффер для сохранения оригинальных байт
char originalBytes[13];

void SetHook();

// Функция, заменяющая оригинальную
HANDLE HookCreateFileA(
	LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
	
	printf("CreateFileA function is hooked! Filename: %s\n", lpFileName);
	
	HMODULE hKernel32;
	HANDLE result;

	WriteProcessMemory(
		GetCurrentProcess(), 
		(LPVOID)hookedAddress, 
		originalBytes, 
		13, 
		NULL
	);

	result = CreateFileA(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);

	SetHook();
	return result;
}

void SetHook() {
    HMODULE hKernel32;
    VOID* myFuncAddress;
    DWORD offset;
    DWORD src;
    DWORD dst;
	
	// mov r11, АДРЕС_ФУНКЦИИ
	// jmp r11
    CHAR patch[13] = { 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3 };
    
    ReadProcessMemory(
        GetCurrentProcess(), 
        (LPCVOID)hookedAddress, 
        originalBytes, 
        13, 
        NULL
    );

    myFuncAddress = &HookCreateFileA;
    
    // Создание патча
    memcpy(patch + 2, &myFuncAddress, 8);
    
    WriteProcessMemory(
        GetCurrentProcess(), 
        (LPVOID)hookedAddress, 
        patch, 
        13, 
        NULL
    );
}

int main() {
	HMODULE hKernel32;
	HANDLE hFile;
	const char* filepath;
	
	filepath = "testfile.tmp";
	hKernel32 = LoadLibraryA("kernel32.dll");
	hookedAddress = GetProcAddress(hKernel32, "CreateFileA");
	
	// Вызов оригинальной функции
	hFile = CreateFileA(
        filepath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    CloseHandle(hFile);
	DeleteFileA(filepath);
	
	// Установка хука
	SetHook();
	
	// Вызов функции после установки хука
	for (int i = 0; i < 10; ++i) {
		hFile = CreateFileA(
			filepath,
			GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		CloseHandle(hFile);
		DeleteFileA(filepath);
	}
	
	// Очистка
	FreeLibrary(hKernel32);
	printf("Good job =)\n");
	return 0;
}