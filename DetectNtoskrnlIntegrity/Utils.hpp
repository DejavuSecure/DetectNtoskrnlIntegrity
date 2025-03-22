#define MiGetPteAddress(_PteBase, _VirtualAddress) (UINT64*)(((_VirtualAddress >> 9) & 0x7FFFFFFFF8) + _PteBase);

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))

extern "C" NTKERNELAPI NTSTATUS NTAPI NtQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

namespace Utils {
    ULONG Replace64(PUCHAR Buffer, ULONG BufferLength, ULONG64 Pattern, ULONG64 ReplaceWith) {
        if (!Buffer || !BufferLength || !Pattern || !ReplaceWith) return 0;

        ULONG ReplacementCount = 0;

        for (ULONG i = 0; i <= BufferLength - 8; i++) {
            if (*(ULONG64*)(Buffer + i) == Pattern) {
                *(ULONG64*)(Buffer + i) = ReplaceWith;
                ReplacementCount++;
            }
        }

        return ReplacementCount;
    }

    bool GetPageTableBases(ULONG64 PageTableBases[4]) {
        ULONG64 PteBase = *(ULONG64*)((ULONG64)MmGetVirtualForPhysical + 0x22);
        ULONG64 PdeBase = (ULONG64)MiGetPteAddress(PteBase, PteBase);
        ULONG64 PdptBase = (ULONG64)MiGetPteAddress(PteBase, PdeBase);
        ULONG64 Pml4Base = (ULONG64)MiGetPteAddress(PteBase, PdptBase);

        PageTableBases[0] = Pml4Base;
        PageTableBases[1] = PdptBase;
        PageTableBases[2] = PdeBase;
        PageTableBases[3] = PteBase;

        return true;
    }

    ULONG64 GetSystemPteAddress(ULONG64 PteBase) {
        ULONG64 SystemCr3 = __readcr3();

        PHYSICAL_ADDRESS PhysicalCr3{};
        PhysicalCr3.QuadPart = SystemCr3;
        ULONG64 VirtualCr3 = (ULONG64)MmGetVirtualForPhysical(PhysicalCr3);

        return (ULONG64)MiGetPteAddress(PteBase, VirtualCr3);
    }

    UINT64 FindPattern(PVOID baseAddress, UINT64 size, const char* pattern)
    {
        UINT8* firstMatch = nullptr;
        const char* currentPattern = pattern;

        UINT8* start = static_cast<UINT8*>(baseAddress);
        UINT8* end = start + size;

        for (UINT8* current = start; current < end; current++)
        {
            UINT8 byte = currentPattern[0]; if (!byte) return reinterpret_cast<UINT64>(firstMatch);
            if (byte == '\?' || *static_cast<UINT8*>(current) == GET_BYTE(byte, currentPattern[1]))
            {
                if (!firstMatch) firstMatch = current;
                if (!currentPattern[2]) return reinterpret_cast<UINT64>(firstMatch);
                ((byte == '\?') ? (currentPattern += 2) : (currentPattern += 3));
            }
            else
            {
                currentPattern = pattern;
                firstMatch = nullptr;
            }
        }

        return 0;
    }

    UINT64 FindPatternImage(PVOID base, const char* pattern, const char* segment)
    {
        UINT64 match = 0;

        PIMAGE_NT_HEADERS64 headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<UINT64>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
        for (ULONG64 i = 0; i < headers->FileHeader.NumberOfSections; ++i)
        {
            PIMAGE_SECTION_HEADER section = &sections[i];
            if (memcmp(section->Name, segment, strlen(segment)) == 0)
            {
                match = FindPattern(reinterpret_cast<void*>(reinterpret_cast<UINT64>(base) + section->VirtualAddress), section->Misc.VirtualSize, pattern);
                if (match) break;
            }
        }

        return match;
    }

    PSYSTEM_SERVICE_TABLE FindKeServiceDescriptorTable64(ULONG64 pKernelBase)
    {
        // .text: KiSystemCall64	
        // 4C 8D 15 ? ? ? ? | lea r10, KeServiceDescriptorTable
        // 4C 8D 1D ? ? ? ? | lea r11, KeServiceDescriptorTableShadow
        // F7 43 ?  ? ? ? ? | test dword ptr [rbx+?], ?

        UINT64 p_lea_r10_r11 = FindPatternImage((PVOID)pKernelBase, "4C 8D 15 ? ? ? ? 4C 8D 1D ? ? ? ? F7 43", ".text");
        if (!p_lea_r10_r11) return 0;

        PSYSTEM_SERVICE_TABLE pCandidateTable = (PSYSTEM_SERVICE_TABLE)(p_lea_r10_r11 + 7 + *(INT32*)(p_lea_r10_r11 + 3));

        if (!MmIsAddressValid(pCandidateTable->ServiceTableBase)) return 0;

        return pCandidateTable;
    }

    bool GetSsdtInfo(ULONG64 pKernelBase, PSSDT_INFO pSsdtInfo) {
        // Find KeServiceDescriptorTable in memory
        PSYSTEM_SERVICE_TABLE pKeServiceDescriptorTable = Utils::FindKeServiceDescriptorTable64(pKernelBase);
        if (!pKeServiceDescriptorTable) {
            DbgPrint("Unable to find KeServiceDescriptorTable\n");
            return false;
        }

        ULONG64 ServiceTableBase = (ULONG64)pKeServiceDescriptorTable->ServiceTableBase;
        if (!ServiceTableBase) {
            DbgPrint("Unable to get ServiceTableBase\n");
            return false;
        }

        // Calculate ServiceTableBase RVA relative to kernel base
        pSsdtInfo->ServiceTableBaseRva = ServiceTableBase - pKernelBase;
        DbgPrint("ServiceTableBase RVA: 0x%llX\n", pSsdtInfo->ServiceTableBaseRva);

        // Get ParamTableBase and NumberOfServices from KeServiceDescriptorTable
        pSsdtInfo->ParamTableBase = (ULONG64)pKeServiceDescriptorTable->ParamTableBase;
        pSsdtInfo->ParamTableBaseRva = (ULONG)(pSsdtInfo->ParamTableBase - pKernelBase);
        pSsdtInfo->TableSize = (ULONG)pKeServiceDescriptorTable->NumberOfServices;

        DbgPrint("ParamTableBase RVA: 0x%X, NumberOfServices: %u\n", pSsdtInfo->ParamTableBaseRva, pSsdtInfo->TableSize);

        return true;
    }

    FILE_INFO ReadFile(wchar_t* WideFilePath) {
        FILE_INFO FileInfo{};

        UNICODE_STRING FilePath;
        RtlInitUnicodeString(&FilePath, WideFilePath);

        OBJECT_ATTRIBUTES ObjectAttributes;
        InitializeObjectAttributes(&ObjectAttributes, &FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

        HANDLE FileHandle; IO_STATUS_BLOCK IoStatusBlock;
        NTSTATUS Status = ZwCreateFile(
            &FileHandle, GENERIC_READ, &ObjectAttributes, &IoStatusBlock, 0,
            FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0
        );

        if (!NT_SUCCESS(Status)) return FileInfo;

        FILE_STANDARD_INFORMATION FileStandardInfo;
        Status = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &FileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

        if (!NT_SUCCESS(Status)) return FileInfo;

        PVOID FileBuffer = ExAllocatePoolWithTag(PagedPool, FileStandardInfo.EndOfFile.QuadPart, 1);
        if (!FileBuffer)
        {
            ZwClose(FileHandle);
            return FileInfo;
        }

        __stosb((PUCHAR)FileBuffer, 0, FileStandardInfo.EndOfFile.QuadPart);

        LARGE_INTEGER ByteOffset = { 0 };
        ByteOffset.QuadPart = 0;
        Status = ZwReadFile(FileHandle, 0, 0, 0, &IoStatusBlock, FileBuffer, FileStandardInfo.EndOfFile.QuadPart, &ByteOffset, 0);

        if (!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(FileBuffer, 1);
            ZwClose(FileHandle);
            return FileInfo;
        }

        ZwClose(FileHandle);

        FileInfo.Buffer = FileBuffer;
        FileInfo.Length = FileStandardInfo.EndOfFile.QuadPart;

        return FileInfo;
    }

    void PerformDynamicReplacements(FILE_INFO NtoskrnlInfo, ULONG64 PteBase, ULONG64 MmPfnDataBase,
        ULONG64 Pml4Base, ULONG64 PdptBase, ULONG64 PdeBase, ULONG64 SystemPteAddress) {
        // Define replacement pairs structure
        struct ReplacementPair {
            ULONG64 Original;
            ULONG64 Replacement;
        };

        // Create replacement array
        ReplacementPair Replacements[] = {
            { 0x0FFFFF6FB7DBEDF68, SystemPteAddress },

            { 0x0FFFFF68000000000, PteBase },
            { 0x0FFFFF6FFFFFFFFFF, PteBase | 0xFFFFFFFFFF },

            { 0x0FFFFDE0000000000, MmPfnDataBase },
            { 0x0FFFFDE0000000008, MmPfnDataBase + 0x08 },
            { 0x0FFFFDE0000000010, MmPfnDataBase + 0x10 },
            { 0x0FFFFDE0000000018, MmPfnDataBase + 0x18 },
            { 0x0FFFFDE0000000022, MmPfnDataBase + 0x22 },
            { 0x0FFFFDE0000000020, MmPfnDataBase + 0x20 },
            { 0x0FFFFDE0000000023, MmPfnDataBase + 0x23 },
            { 0x0FFFFDE0000000028, MmPfnDataBase + 0x28 },
            { 0x0FFFFDE0000000030, MmPfnDataBase + 0x30 },
            { 0x0FFFFDE0000000FFF, MmPfnDataBase + 0xFFF},

            { 0x0FFFFF6FB7DBED000, Pml4Base },
            { 0x0FFFFF6FB7DBED7F8, Pml4Base + 0x7F8 },
            { 0x0FFFFF6FB7DBED800, Pml4Base + 0x800 },
            { 0x0FFFFF6FB7DBEDFFF, Pml4Base + 0xFFF },

            { 0x0FFFFF6FB7DA00000, PdptBase },

            { 0x0FFFFF6FB40000000, PdeBase },
            { 0x0FFFFF6FB5FFFFFF8, PdeBase + 0x1FFFFFF8 },
            { 0x0FFFFF6FB7FFFFFFF, PdeBase + 0x3FFFFFFF },

            { 0x0FFFFF68000000008, PteBase + 0x08 },
            { 0x0FFFFF68000000FFF, PteBase + 0xFFF },
            { 0x0FFFFF70000000000, PteBase + 0x8000000000 },
        };

        // Iterate through all replacement values and perform replacements
        for (size_t i = 0; i < sizeof(Replacements) / sizeof(Replacements[0]); i++) {
            ULONG ReplacementCount = Utils::Replace64(
                (PUCHAR)NtoskrnlInfo.Buffer,
                NtoskrnlInfo.Length,
                Replacements[i].Original,
                Replacements[i].Replacement
            );
            DbgPrint("Replaced %u occurrences of 0x%llX with 0x%llX\n",
                ReplacementCount,
                Replacements[i].Original,
                Replacements[i].Replacement);
        }
    }

    ULONG RvaToFileOffset(PIMAGE_NT_HEADERS64 pNtHeader, PIMAGE_SECTION_HEADER pSectionHeader, ULONG Rva) {
        for (USHORT i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
            if (Rva >= pSectionHeader[i].VirtualAddress &&
                Rva < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData)) {
                return pSectionHeader[i].PointerToRawData + (Rva - pSectionHeader[i].VirtualAddress);
            }
        }
        return 0;
    }

    bool ProcessRelocationBlocks(PIMAGE_DOS_HEADER pDosHeader, ULONG RelocationFileOffset, ULONG RelocationSize,
        PIMAGE_NT_HEADERS64 pNtHeader, PIMAGE_SECTION_HEADER pSectionHeader,
        ULONG64 RelocationDelta, ULONG FileLength) {
        PIMAGE_BASE_RELOCATION pRelocationBlock = (PIMAGE_BASE_RELOCATION)((PUCHAR)pDosHeader + RelocationFileOffset);
        ULONG ProcessedSize = 0;

        while (ProcessedSize < RelocationSize) {
            ULONG EntriesCount = (pRelocationBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            PUSHORT pEntries = (PUSHORT)((PUCHAR)pRelocationBlock + sizeof(IMAGE_BASE_RELOCATION));

            // Process all entries in the relocation block
            for (ULONG i = 0; i < EntriesCount; i++) {
                USHORT Entry = pEntries[i];
                USHORT Type = (Entry >> 12); // Type is high 4 bits
                USHORT Offset = Entry & 0xFFF; // Offset is low 12 bits

                // Process only 64-bit relocations (IMAGE_REL_BASED_DIR64, value 10)
                if (Type == 10) {
                    ULONG EntryRva = pRelocationBlock->VirtualAddress + Offset;
                    ULONG EntryFileOffset = RvaToFileOffset(pNtHeader, pSectionHeader, EntryRva);

                    if (EntryFileOffset != 0 && EntryFileOffset + sizeof(ULONG64) <= FileLength) {
                        PULONG64 pFileAddress = (PULONG64)((PUCHAR)pDosHeader + EntryFileOffset);
                        ULONG64 OriginalValue = *pFileAddress;
                        ULONG64 RelocatedValue = OriginalValue + RelocationDelta;
                        *pFileAddress = RelocatedValue;
                    }
                }
            }

            // Move to next relocation block
            ProcessedSize += pRelocationBlock->SizeOfBlock;
            pRelocationBlock = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRelocationBlock + pRelocationBlock->SizeOfBlock);
        }

        return true;
    }

    bool ProcessRelocations(FILE_INFO NtoskrnlInfo, ULONG64 pKernelBase) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)NtoskrnlInfo.Buffer;
        PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

        // Calculate relocation delta (memory base - expected base)
        ULONG64 RelocationDelta = pKernelBase - pNtHeader->OptionalHeader.ImageBase;
        DbgPrint("Relocation delta: 0x%llX\n", RelocationDelta);

        // Process relocation table
        ULONG RelocationRva = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        ULONG RelocationSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (RelocationRva && RelocationSize) {
            // Convert RVA to file offset
            ULONG RelocationFileOffset = RvaToFileOffset(pNtHeader, pSectionHeader, RelocationRva);
            if (RelocationFileOffset == 0) {
                DbgPrint("Cannot find relocation table file offset\n");
                return false;
            }

            // Process all relocation blocks
            return ProcessRelocationBlocks(pDosHeader, RelocationFileOffset, RelocationSize,
                pNtHeader, pSectionHeader, RelocationDelta, NtoskrnlInfo.Length);
        }

        return true;
    }

    bool ProcessSsdt(FILE_INFO NtoskrnlInfo, ULONG64 pKernelBase, SSDT_INFO SsdtInfo) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)NtoskrnlInfo.Buffer;
        PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

        // Find ServiceTableBase in file
        ULONG FileServiceTableOffset = RvaToFileOffset(pNtHeader, pSectionHeader, SsdtInfo.ServiceTableBaseRva);
        if (FileServiceTableOffset == 0) {
            DbgPrint("Cannot locate KiServiceTable in file\n");
            return false;
        }
        ULONG64 FileServiceTableBase = (ULONG64)pDosHeader + FileServiceTableOffset;

        // Find ParamTableBase in file
        ULONG FileParamTableOffset = RvaToFileOffset(pNtHeader, pSectionHeader, SsdtInfo.ParamTableBaseRva);
        if (FileParamTableOffset == 0) {
            DbgPrint("Cannot locate ParamTableBase in file\n");
            return false;
        }
        PUCHAR FileParamTable = (PUCHAR)pDosHeader + FileParamTableOffset;

        DbgPrint("KiServiceTable in file: 0x%llX, offset: 0x%X\n", FileServiceTableBase, FileServiceTableOffset);
        DbgPrint("ParamTableBase in file: 0x%p, offset: 0x%X\n", FileParamTable, FileParamTableOffset);

        // Process SSDT entries (Windows 10+ style)
        for (ULONG i = 0; i < SsdtInfo.TableSize; i++) {
            // Windows 10+ format (4 bytes per entry)
            ULONG FileEntryValue = *((PULONG)((PUCHAR)FileServiceTableBase + i * 4));
            UCHAR ParamCookie = FileParamTable[i];

            // Calculate FunctionCookie based on Windows 10+ rules
            ULONG_PTR FunctionCookie = FileEntryValue - (ULONG)(FileServiceTableBase - (ULONG64)pDosHeader);

            // Calculate compacted value
            ULONG CompactedValue = (16 * FunctionCookie) | (ParamCookie >> 2);

            // Replace value in file
            *((PULONG)((PUCHAR)FileServiceTableBase + i * 4)) = CompactedValue;
        }

        return true;
    }

    enum class SpectreMitigationMode {
        None = 0,
        Mode1 = 1,
        Mode2 = 2
    };

    SpectreMitigationMode CheckForSpectreMitigation(PUCHAR MemoryData, PUCHAR FileData, ULONG Offset, ULONG64 DataBaseAddr, ULONG Size, bool IsExecutableSection) {
        if (!IsExecutableSection) return SpectreMitigationMode::None;

        // First check pattern 1: starting with "4c 8b" (mov r10) - prioritize checking this pattern
        if (Offset + 1 < Size && MemoryData[Offset] == 0x4c && MemoryData[Offset + 1] == 0x8b) {
            // Use hde64 to disassemble instructions in both file and memory starting from the difference point
            hde64s FileInstr1, FileInstr2;
            hde64s MemInstr1, MemInstr2;

            // Disassemble two instructions from the file
            ULONG FileInstr1Len = hde64_disasm(FileData + Offset, &FileInstr1);
            ULONG FileInstr2Len = 0;

            ULONG MemInstr1Len = 0;
            ULONG MemInstr2Len = 0;

            if (FileInstr1Len > 0) {
                FileInstr2Len = hde64_disasm(FileData + Offset + FileInstr1Len, &FileInstr2);

                // Disassemble two instructions from memory
                MemInstr1Len = hde64_disasm(MemoryData + Offset, &MemInstr1);
                if (MemInstr1Len > 0) {
                    MemInstr2Len = hde64_disasm(MemoryData + Offset + MemInstr1Len, &MemInstr2);

                    // Check if it matches the Spectre Mitigation pattern
                    if (FileInstr1Len > 0 && FileInstr2Len > 0 &&
                        MemInstr1Len > 0 && MemInstr2Len > 0) {

                        // Check if the total instruction length is consistent
                        if (FileInstr1Len + FileInstr2Len == MemInstr1Len + MemInstr2Len) {

                            // Directly check if the file contains a call qword ptr [] pattern (0xFF 0x15)
                            bool FileIsCallIndirect = (FileInstr1.opcode == 0xFF && FileInstr1.modrm == 0x15);

                            // Check if the second instruction in the file is a nop instruction
                            bool FileSecondIsNop = (FileInstr2.opcode == 0x90 || // Single-byte nop
                                (FileInstr2.opcode == 0x0F && FileInstr2.opcode2 == 0x1F)); // Multi-byte nop

                            // Check if the memory contains a mov r10, [] pattern
                            bool MemIsMoveR10 = (MemoryData[Offset] == 0x4c && MemoryData[Offset + 1] == 0x8b && MemoryData[Offset + 2] == 0x15);

                            // Check if the second instruction in memory is a call instruction (0xE8)
                            bool MemSecondIsCall = (MemInstr2.opcode == 0xE8);

                            // If the above conditions are met, identify as Spectre Mitigation Mode 1
                            if (FileIsCallIndirect && FileSecondIsNop &&
                                MemIsMoveR10 && MemSecondIsCall) {

                                // Successfully detected Mode 1
                                return SpectreMitigationMode::Mode1;
                            }
                        }
                    }
                }
            }
        }

        // If pattern 1 doesn't match, check pattern 2: starting with "48 FF 25" (rex.w jmp qword ptr [rip+?])
        if (Offset + 2 < Size && FileData[Offset] == 0x48 && FileData[Offset + 1] == 0xFF && FileData[Offset + 2] == 0x25) {
            // Check if there are consecutive CC (int3) padding in the file
            bool HasNopPadding = false;
            if (Offset + 14 < Size) {  // 6 bytes indirect jump + at least 5 bytes of CC padding
                bool AllCC = true;
                for (int k = 0; k < 5; k++) {
                    if (FileData[Offset + 7 + k] != 0xCC) {
                        AllCC = false;
                        break;
                    }
                }
                HasNopPadding = AllCC;
            }

            // Check if the memory contains the pattern "4c 8b 15 ? ? ? ? e9 ? ? ? ?"
            bool HasSpectreMitigation = false;
            if (Offset + 11 < Size &&
                MemoryData[Offset] == 0x4C && MemoryData[Offset + 1] == 0x8B && MemoryData[Offset + 2] == 0x15 &&
                MemoryData[Offset + 7] == 0xE9) {  // Check if the second instruction is a direct jmp
                HasSpectreMitigation = true;
            }

            if (HasNopPadding && HasSpectreMitigation) {
                // Successfully detected Mode 2
                return SpectreMitigationMode::Mode2;
            }
        }

        return SpectreMitigationMode::None;
    }

    bool ShouldSkipSection(const char* SectionName) {
        return strncmp(SectionName, ".idata", 7) == 0 ||
            strncmp(SectionName, ".edata", 7) == 0 ||
            strncmp(SectionName, "GFIDS", 6) == 0 ||
            strncmp(SectionName, "MINIEX", 7) == 0 ||
            strncmp(SectionName, "INIT", 5) == 0 ||
            strncmp(SectionName, ".rsrc", 5) == 0 ||
            strncmp(SectionName, ".reloc", 7) == 0;
    }

    bool ValidateReadOnlySections(ULONG64 pKernelBase, FILE_INFO NtoskrnlInfo) {
        PIMAGE_DOS_HEADER pDosHeader1 = (PIMAGE_DOS_HEADER)pKernelBase;
        PIMAGE_DOS_HEADER pDosHeader2 = (PIMAGE_DOS_HEADER)NtoskrnlInfo.Buffer;

        PIMAGE_NT_HEADERS64 pNtHeader1 = (PIMAGE_NT_HEADERS64)((PUCHAR)pDosHeader1 + pDosHeader1->e_lfanew);
        PIMAGE_NT_HEADERS64 pNtHeader2 = (PIMAGE_NT_HEADERS64)((PUCHAR)pDosHeader2 + pDosHeader2->e_lfanew);

        PIMAGE_SECTION_HEADER pSectionHeader1 = IMAGE_FIRST_SECTION(pNtHeader1);
        PIMAGE_SECTION_HEADER pSectionHeader2 = IMAGE_FIRST_SECTION(pNtHeader2);

        // Iterate through read-only sections in file and compare with memory
        for (USHORT i = 0; i < pNtHeader2->FileHeader.NumberOfSections; i++) {
            if (!(pSectionHeader2[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
                // Skip specific sections
                if (ShouldSkipSection((const char*)pSectionHeader2[i].Name)) {
                    DbgPrint("Skipping section validation: %s\n", pSectionHeader2[i].Name);
                    continue;
                }

                if (memcmp(pSectionHeader1[i].Name, pSectionHeader2[i].Name, IMAGE_SIZEOF_SHORT_NAME)) {
                    DbgPrint("Ntoskrnl integrity check failed: read-only section name %s\n", pSectionHeader1[i].Name);
                    return false;
                }

                PUCHAR SectionData1 = (PUCHAR)pDosHeader1 + pSectionHeader1[i].VirtualAddress;
                PUCHAR SectionData2 = (PUCHAR)pDosHeader2 + pSectionHeader2[i].PointerToRawData;

                // Compare byte by byte
                ULONG MinSize = min(pSectionHeader1[i].SizeOfRawData, pSectionHeader2[i].SizeOfRawData);
                bool DifferenceFound = false;
                bool IsExecutableSection = (pSectionHeader2[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

                // In ValidateReadOnlySections function:
                for (ULONG j = 0; j < MinSize; j++) {
                    if (SectionData1[j] != SectionData2[j]) {
                        // Check for Spectre Mitigation pattern
                        SpectreMitigationMode MitigationMode = CheckForSpectreMitigation(
                            SectionData1,             // Memory data
                            SectionData2,             // File data
                            j,                        // Current offset
                            (ULONG64)(SectionData1 + j) - (ULONG64)pDosHeader1,  // Base address for correct reporting
                            MinSize,                  // Min size
                            IsExecutableSection       // Is executable section
                        );

                        if (MitigationMode != SpectreMitigationMode::None) {
                            // Handle based on specific mode detected
                            if (MitigationMode == SpectreMitigationMode::Mode1) {
                                // Mode 1: Use actual instruction length
                                hde64s FileInstr1, FileInstr2;
                                ULONG FileInstr1Len = hde64_disasm(SectionData2 + j, &FileInstr1);
                                ULONG FileInstr2Len = 0;
                                if (FileInstr1Len > 0) {
                                    FileInstr2Len = hde64_disasm(SectionData2 + j + FileInstr1Len, &FileInstr2);

                                    // Skip using actual instruction length
                                    ULONG TotalSkip = FileInstr1Len + FileInstr2Len;
                                    if (j + TotalSkip < MinSize) {
                                        j += (TotalSkip - 1);  // -1 because loop will increment j
                                    }
                                    else {
                                        j = MinSize - 1;
                                    }
                                }
                            }
                            else if (MitigationMode == SpectreMitigationMode::Mode2) {
                                // Mode 2: Use fixed 11 bytes skip
                                if (j + 11 < MinSize) {
                                    j += 11;  // Loop will increment j
                                }
                                else {
                                    j = MinSize - 1;
                                }
                            }
                            continue;  // Skip to next iteration
                        }

                        // Not a Spectre Mitigation pattern, handle as difference
                        DifferenceFound = true;

                        // Calculate relative addresses
                        ULONG64 RelativeAddr1 = (ULONG64)(SectionData1 + j) - (ULONG64)pDosHeader1;
                        ULONG64 RelativeAddr2 = (ULONG64)(SectionData2 + j) - (ULONG64)pDosHeader2;

                        DbgPrint("Section %s data mismatch: memory relative addr 0x%llX, file relative addr 0x%llX, values: 0x%02X vs 0x%02X\n",
                            pSectionHeader1[i].Name,
                            RelativeAddr1,
                            RelativeAddr2,
                            SectionData1[j],
                            SectionData2[j]);

                        break;
                    }
                }

                if (DifferenceFound) {
                    DbgPrint("Ntoskrnl integrity check failed: section %s\n", pSectionHeader1[i].Name);
                    return false;
                }

                DbgPrint("Section validation passed: %s\n", pSectionHeader1[i].Name);
            }
        }

        return true;
    }

    PVOID GetModuleBase(const char* ImageName) {
        ULONG BufferSize = 0;
        NTSTATUS Status = 0;

        Status = NtQuerySystemInformation(11, 0, 0, &BufferSize);
        if (!NT_SUCCESS(Status) && Status != 0xC0000004) return 0;

        PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(PagedPool, BufferSize, 1);
        if (!pModuleInfo) return 0;

        Status = NtQuerySystemInformation(11, pModuleInfo, BufferSize, &BufferSize);
        if (!NT_SUCCESS(Status)) return 0;

        ULONG64 Base = 0;
        for (int i = 0; i < pModuleInfo->Count; i++) {
            if (strstr(pModuleInfo->Module[i].ImageName, ImageName))
                Base = (ULONG64)pModuleInfo->Module[i].Base;
            if (Base) break;
        }

        ExFreePoolWithTag(pModuleInfo, 1);

        return (PVOID)Base;
    }
}