#include <ntifs.h>
#include <intrin.h>
#include <ntimage.h>

#include "hde64/hde64.h"

#include "Structs.h"
#include "Utils.hpp"

bool DetectNtoskrnlIntegrity(ULONG64 pKernelBase) {
    // Get page table bases
    ULONG64 PageTableBases[4];
    Utils::GetPageTableBases(PageTableBases);

    ULONG64 Pml4Base = PageTableBases[0];
    ULONG64 PdptBase = PageTableBases[1];
    ULONG64 PdeBase = PageTableBases[2];
    ULONG64 PteBase = PageTableBases[3];

    // Print page table bases
    DbgPrint("Pml4Base %p\n", PageTableBases[0]);
    DbgPrint("PdptBase %p\n", PageTableBases[1]);
    DbgPrint("PdeBase %p\n", PageTableBases[2]);
    DbgPrint("PteBase %p\n", PageTableBases[3]);

    // Get CR3 information
    ULONG64 SystemPteAddress = Utils::GetSystemPteAddress(PteBase);
    ULONG64 MmPfnDataBase = *(ULONG64*)((ULONG64)&MmGetVirtualForPhysical + 0x10) - 8;

    // Get SSDT information
    SSDT_INFO SsdtInfo;
    if (!Utils::GetSsdtInfo(pKernelBase, &SsdtInfo)) return false;

    // Read the ntoskrnl.exe file
    FILE_INFO NtoskrnlInfo = Utils::ReadFile(L"\\??\\C:\\Windows\\System32\\ntoskrnl.exe");
    if (!NtoskrnlInfo.Length) return false;

    // Perform dynamic address replacements
    Utils::PerformDynamicReplacements(NtoskrnlInfo, PteBase, MmPfnDataBase, Pml4Base, PdptBase, PdeBase, SystemPteAddress);

    // Process relocations
    if (!Utils::ProcessRelocations(NtoskrnlInfo, pKernelBase)) return false;

    // Process SSDT
    if (!Utils::ProcessSsdt(NtoskrnlInfo, pKernelBase, SsdtInfo)) return false;

    // Validate read-only sections
    if (!Utils::ValidateReadOnlySections(pKernelBase, NtoskrnlInfo)) return false;

    return true;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    DbgPrint("ntoskrnl.exe integrity check example unloaded!\n");
    // https://www.dejavu-secure.com/
    // https://github.com/DejavuSecure
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    pDriverObject->DriverUnload = DriverUnload;

    DbgPrint("ntoskrnl.exe integrity check example from dejavu-secure.com!\n");
    // https://www.dejavu-secure.com/
    // https://github.com/DejavuSecure

    PVOID NtoskrnlBase = Utils::GetModuleBase("ntoskrnl.exe");
    if (!NtoskrnlBase) return STATUS_UNSUCCESSFUL;

    if (DetectNtoskrnlIntegrity((ULONG64)NtoskrnlBase)) {
        DbgPrint("ntoskrnl.exe integrity check passed.\n");
    }
    else {
        DbgPrint("ntoskrnl.exe integrity check failed!\n");
    }

    return STATUS_SUCCESS;
}