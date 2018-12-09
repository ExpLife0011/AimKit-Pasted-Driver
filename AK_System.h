#pragma once
#include "AK_Main.h"
#define INVALID_HANDLE_VALUE (HANDLE)-1
#define MAX_PATH2 4096
/*
typedef struct _FILE_BOTH_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;
*/

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
	ULONG  Length;
	ULONG  CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;


typedef struct _RTL_PROCESS_MODULE_INFORMATION2
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION2, *PRTL_PROCESS_MODULE_INFORMATION2;


typedef struct _RTL_PROCESS_MODULES2
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION2 Modules[1];
} RTL_PROCESS_MODULES2, *PRTL_PROCESS_MODULES2;

typedef struct sKernDriverList
{
	int Set;
	DWORD64 ImageBase;
	int ImageSize;
	char NtSysName[512];
	char NtSysPath[1024];
}sKernDriverList, *PsKernDriverList;


typedef struct _MEM_CHECK_PAGE_PROTECT
{
	ULONG      pid;
	ULONGLONG  memaddr;      
} MEM_CHECK_PAGE_PROTECT, *PMEM_CHECK_PAGE_PROTECT;

typedef struct
{
	char ModBaseStr[256];
	ULONG pid; 
} MODBASE, *PMODBASE;

int GetDriversList(sKernDriverList* iList);
int GetMemPageInfo(PMEM_CHECK_PAGE_PROTECT MemInfo, OUT MEMORY_BASIC_INFORMATION *OProtect);
NTSTATUS GetModuleBase(IN PMODBASE pMod, OUT PMODBASE pResult);
ULONG SearchForDrivers(LPSTR lpPath, char *FileArray);
int CheckIfPIDRunning(HANDLE pid);
int AKTerminateProcess(HANDLE pid);