#include "AK_Main.h"
GET_PROCESS_IMAGE_NAME PsGetProcessImageFileName_D;
PsLookupProcessByProcessIdP PsLookupProcessByProcessId_D;
PsGetProcessSectionBaseAddressP PsGetProcessSectionBaseAddress_D;
PsGetCurrentProcessIdP PsGetCurrentProcessId_D;
PsGetCurrentProcessP PsGetCurrentProcess_D;
ZwQueryInformationProcessP ZwQueryInformationProcess_D;
ZwQuerySystemInformationP ZwQuerySystemInformation_D;
MmCopyVirtualMemoryP MmCopyVirtualMemory_D;
ZwQueryDirectoryObjectP ZwQueryDirectoryObject_D;
KeStackAttachProcessP KeStackAttachProcess_D;
KeUnstackDetachProcessP KeUnstackDetachProcess_D;

FltRegisterFilterP FltRegisterFilter_D;
FltUnregisterFilterP FltUnregisterFilter_D;
FltStartFilteringP FltStartFiltering_D;
FltSetCallbackDataDirtyP FltSetCallbackDataDirty_D;
FltReleaseFileNameInformationP FltReleaseFileNameInformation_D;
FltGetFileNameInformationP FltGetFileNameInformation_D;
FltParseFileNameInformationP FltParseFileNameInformation_D;

int FastMemCpyPID = 0;
PEPROCESS pFastProcess = 0;
int LastDrive = 0;
int SpooferRunning = 0;
int ObsRunning = 0;
char HDSerial[256] = { 0 };
/*
#pragma alloc_text(PAGE, AKInitalize)
#pragma alloc_text(PAGE, AKSetCallbacks)
*/

void AKInitalize()
{
	VMProtectBeginUltra("AKInitalize");
	UNICODE_STRING routineName;
	// Get function pointers to various functions we use
	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"PsGetProcessImageFileName"));
	PsGetProcessImageFileName_D = (GET_PROCESS_IMAGE_NAME)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"PsLookupProcessByProcessId"));
	PsLookupProcessByProcessId_D = (PsLookupProcessByProcessIdP)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"PsGetCurrentProcess"));
	PsGetCurrentProcess_D = (PsGetCurrentProcessP)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"PsGetCurrentProcessId"));
	PsGetCurrentProcessId_D = (PsGetCurrentProcessIdP)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"ZwQueryInformationProcess"));
	ZwQueryInformationProcess_D = (ZwQueryInformationProcessP)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"ZwQuerySystemInformation"));
	ZwQuerySystemInformation_D = (ZwQuerySystemInformationP)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"MmCopyVirtualMemory"));
	MmCopyVirtualMemory_D = (MmCopyVirtualMemoryP)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"PsGetProcessSectionBaseAddress"));
	PsGetProcessSectionBaseAddress_D = (PsGetProcessSectionBaseAddressP)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"KeStackAttachProcess"));
	KeStackAttachProcess_D = (KeStackAttachProcessP)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"KeUnstackDetachProcess"));
	KeUnstackDetachProcess_D = (KeUnstackDetachProcessP)MmGetSystemRoutineAddress(&routineName);


	RtlInitUnicodeString(&routineName, VMProtectDecryptStringW(L"ZwQueryDirectoryObject"));
	ZwQueryDirectoryObject_D = (ZwQueryDirectoryObjectP)MmGetSystemRoutineAddress(&routineName);
	if (ZwQueryDirectoryObject_D == NULL)
	{
		DPRINT("ZwQueryDirectoryObject failed\n");
	}
	else
	{
		DPRINT("ZwQueryDirectoryObject 0x%X\n", ZwQueryDirectoryObject_D);
	}


	FltRegisterFilter_D = (FltRegisterFilterP)FltGetRoutineAddress(VMProtectDecryptStringA("FltRegisterFilter"));
	FltUnregisterFilter_D = (FltUnregisterFilterP)FltGetRoutineAddress(VMProtectDecryptStringA("FltUnregisterFilter"));
	FltStartFiltering_D = (FltStartFilteringP)FltGetRoutineAddress(VMProtectDecryptStringA("FltStartFiltering"));
	FltSetCallbackDataDirty_D = (FltSetCallbackDataDirtyP)FltGetRoutineAddress(VMProtectDecryptStringA("FltSetCallbackDataDirty"));
	FltReleaseFileNameInformation_D = (FltReleaseFileNameInformationP)FltGetRoutineAddress(VMProtectDecryptStringA("FltReleaseFileNameInformation"));
	FltGetFileNameInformation_D = (FltGetFileNameInformationP)FltGetRoutineAddress(VMProtectDecryptStringA("FltGetFileNameInformation"));
	FltParseFileNameInformation_D = (FltParseFileNameInformationP)FltGetRoutineAddress(VMProtectDecryptStringA("FltParseFileNameInformation"));
	VMProtectEnd();
}

void AKSetCallbacks()
{
	ClearOBAuthPids();
	NTSTATUS status1 = RegisterCallbackFunction();
	if (!NT_SUCCESS(status1))
	{
		DPRINT("AKDriver: Faild to RegisterCallbackFunction .status : 0x%X \n", status1);
	}
	NTSTATUS status2 = RegisterPostCallbackFunction();
	if (!NT_SUCCESS(status2))
	{
		DPRINT("AKDriver: Faild to RegisterPostCallbackFunction .status : 0x%X \n", status2);
	}
	ObsRunning = 1;
}



/*
FltRegisterFilterP FltRegisterFilter_D;
FltUnregisterFilterP FltUnregisterFilter_D;
FltStartFilteringP FltStartFiltering_D;
FltSetCallbackDataDirtyP FltSetCallbackDataDirty_D;
FltReleaseFileNameInformationP FltReleaseFileNameInformation_D;
FltGetFileNameInformationP FltGetFileNameInformation_D;
FltParseFileNameInformationP FltParseFileNameInformation_D;
*/