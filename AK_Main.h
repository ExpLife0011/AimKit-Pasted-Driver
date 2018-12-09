#pragma once
//#include <ntddk.h>
#include <stdio.h>
#include <stdarg.h>
#include <ntdef.h>
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddscsi.h>
#include "NativeEnums.h"
#include "BlackBoneDrv.h"

extern UNICODE_STRING deviceName;
extern UNICODE_STRING deviceLink;
extern UNICODE_STRING DriverNameU;
extern UNICODE_STRING DriverNameFN;
extern UNICODE_STRING RedirectDriverTo;
extern char DriverAnsiName[256];
extern int RUST_PID;
extern int RUST_PID_RUNNING;

#include "AK_Minifilter.h"
#include "AK_SpoofDrive.h"
#include "AK_System.h"
#include "AK_Rc4.h"
#include "AK_ImageNotify.h"
#include "AK_ThreadNotify.h"
#include "AK_ProcNotify.h"
#include "AK_OBCallbacks.h"
#include "AK_Util.h"
#include "AK_Sha256.h"
#include "AK_Auth.h"
#include "VMProtectDDK.h"
#include "AK_SpoofMac.h"

extern DWORD64 mono_realbase;
extern int LastDrive;
extern int SpooferRunning;
extern int ObsRunning;
extern char HDSerial[256];

//#define LOG_RC4Key "8f66e65d20168d901ad649bec552b41bbfb26847abd7a13ad9af76bdbc2c67a2"
//#define LOG_PATH L"\\??\\C:\\AKDriver.txt"




//disable debug console logging via debugview, it doesn't make sense to encrypt it, so let's stick to just files
/*
#ifdef DBG
#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#else
#define DPRINT(...)
#endif
*/
//#define DBP

#ifdef DBP
//#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
//#define DPRINT(format, ...) AppendLogFile(format, __VA_ARGS__)
#else
#define DPRINT(...)
#endif



#ifdef DBP2
#define AKDPRINT(format, ...) AppendLogFile(format, __VA_ARGS__)
#else
#define AKDPRINT(...)
#endif


//extern char RequestCryptKey[];
//extern char GHSalt[];
extern char GHProcessName[256];
extern int GHProcessSet;
extern int GHPid;
extern int GH_SigAuthed;

//-----------------------------------------------
//  Defines
//-----------------------------------------------

//Process Security and Access Rights
#define PROCESS_CREATE_THREAD  (0x0002)
#define PROCESS_CREATE_PROCESS (0x0080)
#define PROCESS_TERMINATE      (0x0001)
#define PROCESS_VM_WRITE       (0x0020)
#define PROCESS_VM_READ        (0x0010)
#define PROCESS_VM_OPERATION   (0x0008)
#define PROCESS_SUSPEND_RESUME (0x0800)

//event for user-mode processes to monitor
//#define BSProcMon_Event     L"\\BaseNamedObjects\\BTProcMonProcessEvent" 

#define MAXIMUM_FILENAME_LENGTH 256
//-----------------------------------------------
// callback 
//-----------------------------------------------
typedef struct _OB_REG_CONTEXT {
	__in USHORT Version;
	__in UNICODE_STRING Altitude;
	__in USHORT ulIndex;
	OB_OPERATION_REGISTRATION *OperationRegistration;
} REG_CONTEXT, *PREG_CONTEXT;


//-----------------------------------------------
// PID2ProcName 
//-----------------------------------------------

/*
extern UCHAR *PsGetProcessImageFileName(IN PEPROCESS Process);

extern   NTSTATUS PsLookupProcessByProcessId(
	HANDLE ProcessId,
	PEPROCESS *Process
);
*/
typedef PCHAR(*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);
GET_PROCESS_IMAGE_NAME gGetProcessImageFileName;

LPSTR GetProcessNameFromPid(HANDLE pid);


typedef PCHAR(__fastcall *GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);
typedef NTSTATUS(__fastcall *PsLookupProcessByProcessIdP)(HANDLE ProcessId, _Out_ PEPROCESS *Process);
typedef HANDLE(__fastcall *PsGetCurrentProcessIdP)();
typedef PEPROCESS(__fastcall *PsGetCurrentProcessP)(void);
typedef NTSTATUS(NTAPI* ZwQueryInformationProcessP)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);


typedef NTSTATUS(__fastcall *ZwQueryDirectoryObjectP)(
	_In_      HANDLE  DirectoryHandle,
	_Out_opt_ PVOID   Buffer,
	_In_      ULONG   Length,
	_In_      BOOLEAN ReturnSingleEntry,
	_In_      BOOLEAN RestartScan,
	_Inout_   PULONG  Context,
	_Out_opt_ PULONG  ReturnLength
);

/*
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 11,
	SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
*/

typedef NTSTATUS(NTAPI* ZwQuerySystemInformationP)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);


typedef NTSTATUS(__fastcall *MmCopyVirtualMemoryP)(PEPROCESS a1, void *a2, PEPROCESS *a3, void *a4, ULONGLONG a5, KPROCESSOR_MODE a6, ULONG *a7);

typedef PVOID(__fastcall *PsGetProcessSectionBaseAddressP)(PEPROCESS Process);
typedef void*(__fastcall *KeStackAttachProcessP)(PRKPROCESS Process, PKAPC_STATE ApcState);
typedef void*(__fastcall *KeUnstackDetachProcessP)(PKAPC_STATE ApcState);



typedef NTSTATUS(__fastcall *FltRegisterFilterP)(_In_ PDRIVER_OBJECT Driver,_In_  const FLT_REGISTRATION *Registration,_Out_ PFLT_FILTER *RetFilter);
typedef VOID(__fastcall *FltUnregisterFilterP)(_In_ PFLT_FILTER Filter);
typedef NTSTATUS(__fastcall *FltStartFilteringP)(_In_ PFLT_FILTER Filter);
typedef VOID(__fastcall *FltSetCallbackDataDirtyP)(_Inout_ PFLT_CALLBACK_DATA Data);
typedef VOID(__fastcall *FltReleaseFileNameInformationP)(_In_ PFLT_FILE_NAME_INFORMATION FileNameInformation);
typedef NTSTATUS(__fastcall *FltGetFileNameInformationP)(_In_ PFLT_CALLBACK_DATA CallbackData,_In_ FLT_FILE_NAME_OPTIONS NameOptions,_Out_ PFLT_FILE_NAME_INFORMATION *FileNameInformation);
typedef NTSTATUS(__fastcall *FltParseFileNameInformationP)(_Inout_ PFLT_FILE_NAME_INFORMATION FileNameInformation);

extern FltRegisterFilterP FltRegisterFilter_D;
extern FltUnregisterFilterP FltUnregisterFilter_D;
extern FltStartFilteringP FltStartFiltering_D;
extern FltSetCallbackDataDirtyP FltSetCallbackDataDirty_D;
extern FltReleaseFileNameInformationP FltReleaseFileNameInformation_D;
extern FltGetFileNameInformationP FltGetFileNameInformation_D;
extern FltParseFileNameInformationP FltParseFileNameInformation_D;

//-----------------------------------------------
//  Forward Declaration
//-----------------------------------------------
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
);



int IsValidDate();
int isRequestValid(char *idata, int idatalen);


extern ZwQueryInformationProcessP ZwQueryInformationProcess_D;
extern ZwQuerySystemInformationP ZwQuerySystemInformation_D;


extern GET_PROCESS_IMAGE_NAME PsGetProcessImageFileName_D;
extern PsLookupProcessByProcessIdP PsLookupProcessByProcessId_D;
extern PsGetCurrentProcessP PsGetCurrentProcess_D;
extern PsGetCurrentProcessIdP PsGetCurrentProcessId_D;
extern MmCopyVirtualMemoryP MmCopyVirtualMemory_D;
extern ZwQueryDirectoryObjectP ZwQueryDirectoryObject_D;
extern PsGetProcessSectionBaseAddressP PsGetProcessSectionBaseAddress_D;
extern KeStackAttachProcessP KeStackAttachProcess_D;
extern KeUnstackDetachProcessP KeUnstackDetachProcess_D;

extern int FastMemCpyPID;
extern PEPROCESS pFastProcess;

void AKInitalize();
void AKSetCallbacks();