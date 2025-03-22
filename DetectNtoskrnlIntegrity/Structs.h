typedef struct _SYSTEM_SERVICE_TABLE {
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONG64 NumberOfServices;
    PVOID ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

typedef struct _SSDT_INFO {
    ULONG64 ServiceTableBaseRva;
    ULONG64 ParamTableBase;
    ULONG ParamTableBaseRva;
    ULONG TableSize;
} SSDT_INFO, * PSSDT_INFO;

typedef struct _FILE_INFO {
    PVOID Buffer;
    ULONG64 Length;
} FILE_INFO, * PFILE_INFO;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    ULONG Reserved[4];
    ULONG64 Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;