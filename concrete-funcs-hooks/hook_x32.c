// x32 Хук функции CreateFileA
// Компилировать так:
// gcc main.c && a.exe

#include <stdio.h>
#include <Windows.h>

// Сигнатура функции взята отсюда:
// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
typedef __stdcall HANDLE (*TypeCreateFileA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

// Адрес хукаемой функции
FARPROC hookedAddress;
// Буффер для сохранения оригинальных байт
char originalBytes[7];

void SetHook();
void print_bytes(const void* address, size_t count);

// Функция, заменяющая оригинальную
HANDLE __stdcall HookCreateFileA(
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
	TypeCreateFileA FuncCreateFileA;

	WriteProcessMemory(
		GetCurrentProcess(), 
		(LPVOID)hookedAddress, 
		originalBytes, 
		7, 
		NULL
	);

	hKernel32 = LoadLibrary("kernel32.dll");
	FuncCreateFileA = 
		(TypeCreateFileA) GetProcAddress(hKernel32, "CreateFileA");

	return (FuncCreateFileA) (
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);
}


int main() {
	TypeCreateFileA FuncCreateFileA;
	HMODULE hKernel32;
	HANDLE hFile;
	const char* filepath;
	
	filepath = "testfile.tmp";
	hKernel32 = LoadLibraryA("kernel32.dll");
	FuncCreateFileA = 
		(TypeCreateFileA) GetProcAddress(hKernel32, "CreateFileA");
	
	
	// Вызов оригинальной функции
	hFile = (FuncCreateFileA) (
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
	hFile = (FuncCreateFileA) (
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
	
	// Очистка
	FreeLibrary(hKernel32);
	printf("Good job =)\n");
	return 0;
}

void SetHook() {
    HMODULE hKernel32;
    VOID* myFuncAddress;
    DWORD offset;
    DWORD src;
    DWORD dst;
	
	// mov ebx, АДРЕС_ФУНКЦИИ
	// jmp ebx
    CHAR patch[7] = { 0xBB, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE3 };
	
    hKernel32 = LoadLibraryA("kernel32.dll");
    hookedAddress = GetProcAddress(hKernel32, "CreateFileA");
    
    ReadProcessMemory(
        GetCurrentProcess(), 
        (LPCVOID)hookedAddress, 
        originalBytes, 
        7, 
        NULL
    );

    myFuncAddress = &HookCreateFileA;
    
    // Создание патча
    memcpy(patch + 1, &myFuncAddress, 4);
    
    WriteProcessMemory(
        GetCurrentProcess(), 
        (LPVOID)hookedAddress, 
        patch, 
        7, 
        NULL
    );
}

void print_bytes(const void* address, size_t count) {
    const unsigned char* ptr = (const unsigned char*)address; 
    for (size_t i = 0; i < count; i++) {
        printf("%02X ", ptr[i]);
    }
    printf("\n");
}