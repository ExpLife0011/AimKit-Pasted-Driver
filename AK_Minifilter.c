#include "AK_Main.h"

/*
#pragma alloc_text(PAGE, NPUnload)
#pragma alloc_text(PAGE, NPPostCreate)
#pragma alloc_text(PAGE, InitMiniFilter)
#pragma alloc_text(PAGE, UnloadFilter)
#pragma alloc_text(PAGE, MJCreatePreOpCallback)
*/

PFLT_FILTER g_pFilterHandle = NULL;
PFLT_PORT 	g_pServerPort = NULL;
PFLT_PORT 	g_pClientPort = NULL;

int EAC_HWID_BYPASS = 1;
int Redirect_DLL ;

//operation registration
const FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{
		IRP_MJ_CREATE,
		0,
		MJCreatePreOpCallback,
		NPPostCreate
	},
	{
		IRP_MJ_OPERATION_END
	}
};

//This defines what we want to filter with FltMgr
const FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks
	NPUnload,                           //  MiniFilterUnload
	NULL,								//  InstanceSetup
	NULL,								//  InstanceQueryTeardown
	NULL,								//  InstanceTeardownStart
	NULL,								//  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};


NTSTATUS UnloadFilter()
{
	FltUnregisterFilter_D(g_pFilterHandle);
	DPRINT("[MiniFilter][DriverUnload]\n");
	return STATUS_SUCCESS;
}

NTSTATUS NPUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();
	//RestoreDriverEntry(DriverObjectP);
	FltUnregisterFilter_D(g_pFilterHandle);

	//if (gHideFileName != NULL)
	//{
	//	ExFreePoolWithTag(gHideFileName, FILE_NAME_TAG);
	//}
	DPRINT("[MiniFilter][DriverUnload]\n");
	return STATUS_SUCCESS;
}

NTSTATUS InitMiniFilter(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{

	DPRINT("FUCKING FILTER IS RUNNING");

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;		//for communication port name
	UNREFERENCED_PARAMETER(RegistryPath);
	//×¢²á¹ýÂËÆ÷
	status = FltRegisterFilter_D(DriverObject,&FilterRegistration,&g_pFilterHandle);
	ASSERT(NT_SUCCESS(status));
	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering_D(g_pFilterHandle);
		if (!NT_SUCCESS(status))
		{
			FltUnregisterFilter_D(g_pFilterHandle);
		}
	}
	_Exit_DriverEntry:
	if (!NT_SUCCESS(status))
	{
		if (NULL != g_pFilterHandle)
		{
			FltUnregisterFilter_D(g_pFilterHandle);
			g_pFilterHandle = NULL;
		}
	}
}

FLT_POSTOP_CALLBACK_STATUS NPPostCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
}


// This is the callback mapped to IRP_MJ_CREATE
FLT_PREOP_CALLBACK_STATUS MJCreatePreOpCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
	//UNICODE_STRING newFileName;
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION nameInfo = 0;
	PUNICODE_STRING FullPath;
	USHORT lastSlashLoc;
	UNICODE_STRING redirectTarget;
	PUNICODE_STRING FileName;
	ANSI_STRING FullPathAnsi;
	int i;
	char filepath[512];
	char strDrivePath[128];



	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();

	// We will replace the file being opened with this file in the same directory
	//RtlInitUnicodeString(&newFileName, L"\\dxgkrnl.sys");

	// Lookup the full path that includes the volume
	// ex: \Device\HardDiskVolume1\targetfile.txt
	status = FltGetFileNameInformation_D(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	if (status != STATUS_SUCCESS) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = FltParseFileNameInformation_D(nameInfo);
	if (status != STATUS_SUCCESS) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//convert to ansi and copy to our buffer, as it's easier to work with ansi strings
	FullPath = &nameInfo->Name;
	RtlUnicodeStringToAnsiString(&FullPathAnsi, &nameInfo->Name, TRUE);
	strcpy(filepath, FullPathAnsi.Buffer);
	RtlFreeAnsiString(&FullPathAnsi);

	
	


	//eac hwid bypass
	//if (EAC_HWID_BYPASS == 1)
	//{
		//DbgPrint("path %s\n", filepath);

	//int cpid = (int)PsGetCurrentProcessId_D();
	//DbgPrint("pid %d name %s", cpid, GetProcessNameFromPid(cpid));
	/*
		if (strstr(GetProcessNameFromPid(cpid), "HWID") != NULL)
		{
			int cpid = (int)PsGetCurrentProcessId_D();
			DbgPrint("pid %d name %s %s", cpid, GetProcessNameFromPid(cpid), filepath);
		}
*/
		//|| strcmp(filepath,"\\Device\\HarddiskVolume2\\")==0 || strcmp(filepath, "\\\\.\\PhysicalDrive1") == 0


	/***********************************************
		if (NULL != strstr(filepath, "DR0") || NULL != strstr(filepath, "DR1") || NULL != strstr(filepath, "DR2") || NULL != strstr(filepath, "\\Harddisk0\\") || NULL != strstr(filepath, "\\Harddisk1\\") || NULL != strstr(filepath, "\\Harddisk2\\"))
		{
			//DbgPrint("blocking path %s\n", filepath);
			FltReleaseFileNameInformation_D(nameInfo);
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			return FLT_PREOP_COMPLETE;
		}
		***********************************************/
		//ToUpper(&filepath);
		
		/*
		for (i = 65; i < 91; i++)
		{
			sprintf(strDrivePath, "\\\\?\\%c:", i);
			if (strcmp(filepath, strDrivePath)==0)
			{
				FltReleaseFileNameInformation_D(nameInfo);
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				return FLT_PREOP_COMPLETE;
			}
		}
		*/
	//}

	//ToLower(&filepath);
	//file we want to redirect
	char *p = strstr(filepath, DriverAnsiName);
	//char *p = strstr(filepath, "dxgkrnl4.sys");
	if (p) {
		////////////DPRINT("Would redirect %s %s %wZ\r\n", filepath, DriverAnsiName, RedirectDriverTo);


		// Find the beginning of just the file name
		lastSlashLoc = FullPath->Length / 2;
		while (lastSlashLoc > 0 && FullPath->Buffer[lastSlashLoc] != L'\\') {
			lastSlashLoc--;
		}

		// Copy the full path, without the file name, to the redirect target path
		// Then add the new file name to the end of that
		// Should end up with something like: \Device\HardDiskVolume1\myfile.txt
		redirectTarget.Length = lastSlashLoc * 2;
		redirectTarget.MaximumLength = lastSlashLoc * 2 + RedirectDriverTo.Length * 2;
		redirectTarget.Buffer = (PWSTR)ExAllocatePool(NonPagedPool, redirectTarget.MaximumLength);
		RtlCopyMemory(redirectTarget.Buffer, FullPath->Buffer, lastSlashLoc * 2);
		RtlAppendUnicodeStringToString(&redirectTarget, &RedirectDriverTo);



		// Throw away the current file name, which should be something like \targetfile.txt
		// and replace with the path of the file we want to open instead
		FileName = &Data->Iopb->TargetFileObject->FileName;
		ExFreePool(FileName->Buffer);
		FileName->Length = 0;
		FileName->MaximumLength = redirectTarget.MaximumLength;
		FileName->Buffer = (PWSTR)ExAllocatePool(NonPagedPool, FileName->MaximumLength);
		RtlCopyUnicodeString(FileName, &redirectTarget);
		ExFreePool(redirectTarget.Buffer);


		// Tell the kernel to reparse this file open so it uses the new file path
		Data->IoStatus.Information = IO_REPARSE;
		Data->IoStatus.Status = STATUS_REPARSE;
		Data->Iopb->TargetFileObject->RelatedFileObject = NULL;

		FltSetCallbackDataDirty_D(Data);
		return FLT_PREOP_COMPLETE;
	}

	//disable hd spoofer
	p = strstr(filepath, VMProtectDecryptStringA("asdfsadfc9asdy89asydas.safsafsfss")); //find
	if (p) {
		if (SpooferRunning == 1)
		{
			UnhookDiskDriver();
		}
	}

	//enablee hd spoofer
	p = strstr(filepath, VMProtectDecryptStringA("fsdf3h548d76.aw9es78yd")); //find
	if (p) {
		if (SpooferRunning != 1)
		{
			HookDiskDriver();
		}
	}

	/***************************************
	Redirect Open Driver Handle To
	*************************************/
	UNICODE_STRING newFileName2;

	//if (Redirect_DLL==1)
	//{
		////////RtlInitUnicodeString(&newFileName2, L"\\Device\\DXGKrnl488"); //redirect to
		RtlInitUnicodeString(&newFileName2, deviceName.Buffer);
		p = strstr(filepath, VMProtectDecryptStringA("fsafasfgdsfd.gdsgfetrfdr")); //find
		if (p) {
			DPRINT("FUCKING REQUEST");
			//////////DPRINT("BlackBone: redirecting %s\n", filepath);

			// Find the beginning of just the file name
			lastSlashLoc = FullPath->Length / 2;
			while (lastSlashLoc > 0 && FullPath->Buffer[lastSlashLoc] != L'\\') {
				lastSlashLoc--;
			}

			// Copy the full path, without the file name, to the redirect target path
			// Then add the new file name to the end of that
			// Should end up with something like: \Device\HardDiskVolume1\myfile.txt
			redirectTarget.Length = newFileName2.Length;
			redirectTarget.MaximumLength = newFileName2.Length * 2;
			redirectTarget.Buffer = (PWSTR)ExAllocatePool(NonPagedPool, redirectTarget.MaximumLength);
			RtlCopyMemory(redirectTarget.Buffer, newFileName2.Buffer, newFileName2.Length);



			// Throw away the current file name, which should be something like \targetfile.txt
			// and replace with the path of the file we want to open instead
			FileName = &Data->Iopb->TargetFileObject->FileName;
			ExFreePool(FileName->Buffer);
			FileName->Length = 0;
			FileName->MaximumLength = redirectTarget.MaximumLength;
			FileName->Buffer = (PWSTR)ExAllocatePool(NonPagedPool, redirectTarget.MaximumLength);
			RtlCopyUnicodeString(FileName, &redirectTarget);
			ExFreePool(redirectTarget.Buffer);


			// Tell the kernel to reparse this file open so it uses the new file path
			Data->IoStatus.Information = IO_REPARSE;
			Data->IoStatus.Status = STATUS_REPARSE;
			Data->Iopb->TargetFileObject->RelatedFileObject = NULL;

			FltSetCallbackDataDirty_D(Data);
			return FLT_PREOP_COMPLETE;
		}
	//}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
