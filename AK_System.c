#include "AK_Main.h"

/*
#pragma alloc_text(PAGE, GetDriversList)
#pragma alloc_text(PAGE, GetMemPageInfo)
#pragma alloc_text(PAGE, GetModuleBase)
*/
int GetDriversList(sKernDriverList* iList)
{
	NTSTATUS status;
	ULONG i;
	int count = 0;

	PRTL_PROCESS_MODULES2 ModuleInfo;
	ModuleInfo = (PRTL_PROCESS_MODULES2)RtlAllocateMemoryV(1024 * 1024); // Allocate memory for the module list
	if (!ModuleInfo)
	{
		return 0;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation_D(11, ModuleInfo, 1024 * 1024, NULL))) // 11 = SystemModuleInformation
	{
		RtlFreeMemoryV(ModuleInfo);
		return 0;
	}

	for (i = 0; i<ModuleInfo->NumberOfModules; i++)
	{

		iList[i].Set = 1;
		strcpy(iList[i].NtSysName, (char *)ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName);
		strcpy(iList[i].NtSysPath, (char *)ModuleInfo->Modules[i].FullPathName);
		iList[i].ImageBase = (DWORD64)ModuleInfo->Modules[i].ImageBase;
		iList[i].ImageSize = ModuleInfo->Modules[i].ImageSize;
		/*
		printf("*****************************************************\n");
		printf("Image base: %#x\n", ModuleInfo->Modules[i].ImageBase);
		printf("Image name: %s\n", ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName);
		printf("Image full path: %s\n", ModuleInfo->Modules[i].FullPathName);
		printf("Image size: %d\n", ModuleInfo->Modules[i].ImageSize);
		printf("*****************************************************\n");
		*/
		count++;
	}

	RtlFreeMemoryV(ModuleInfo);
	return count;
}

int GetMemPageInfo(PMEM_CHECK_PAGE_PROTECT MemInfo, OUT MEMORY_BASIC_INFORMATION *OProtect)
{
	NTSTATUS status = STATUS_SUCCESS;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T length = 0;
	ULONG_PTR memptr = 0;
	PMAP_ENTRY pEntry = NULL;
	unsigned char *p = NULL;
	KAPC_STATE apc;
	PEPROCESS pProcess = NULL;
	CLIENT_ID client_id;
	OBJECT_ATTRIBUTES objAttr;
	HANDLE hProcess;
	if (PsLookupProcessByProcessId_D(MemInfo->pid, &pProcess) == STATUS_INVALID_PARAMETER)
	{
		if (pProcess)
			ObDereferenceObject(pProcess);

		return 0;
	}

	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	client_id.UniqueProcess = MemInfo->pid;
	client_id.UniqueThread = (HANDLE)0;
	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &client_id);
	if (status != STATUS_SUCCESS)
	{
		return 0;
	}

	status = ZwQueryVirtualMemory(hProcess, (PVOID)MemInfo->memaddr, MemoryBasicInformation, OProtect, sizeof(MEMORY_BASIC_INFORMATION), &length);
	ZwClose(hProcess);

	if (pProcess)
		ObDereferenceObject(pProcess);
	return 1;
}

NTSTATUS GetModuleBase(IN PMODBASE pMod, OUT PMODBASE pResult)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS targetProcess = 0;
	PVOID value = 0;
	KAPC_STATE *ka_state = NULL;

	__try
	{
		status = PsLookupProcessByProcessId_D((PVOID)pMod->pid, &targetProcess);
		if (NT_SUCCESS(status))
		{

			ka_state = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC_STATE), BB_POOL_TAG);
			KeStackAttachProcess_D((PRKPROCESS)targetProcess, ka_state);
			value = PsGetProcessSectionBaseAddress_D(targetProcess);

			sprintf(&pResult->ModBaseStr, VMProtectDecryptStringA("%p"), value);

			KeUnstackDetachProcess_D(ka_state);
			ExFreePoolWithTag((void *)ka_state, BB_POOL_TAG);
		}
	}
	__except (GetExceptionCode())
	{
		if (targetProcess)
			ObDereferenceObject(targetProcess);

		KeUnstackDetachProcess_D(ka_state);
		return STATUS_UNHANDLED_EXCEPTION;
	}

	if (targetProcess)
	{
		ObDereferenceObject(targetProcess);
	}

	return status;
}


HANDLE MyFindFirstFile(LPSTR lpDirectory, PFILE_BOTH_DIR_INFORMATION pDir, ULONG uLength)
{
	VMProtectBeginUltra("MyFindFirstFile");
	char strFolder[MAX_PATH2] = { 0 };
	STRING astrFolder;
	UNICODE_STRING ustrFolder;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS ntStatus;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	memset(strFolder, 0, MAX_PATH2);
	strcpy(strFolder, VMProtectDecryptStringA("\\??\\"));
	strcat(strFolder, lpDirectory);
	RtlInitString(&astrFolder, strFolder);
	if (RtlAnsiStringToUnicodeString(&ustrFolder, &astrFolder, TRUE) == 0)
	{
		InitializeObjectAttributes(&oa, &ustrFolder, OBJ_CASE_INSENSITIVE, NULL, NULL);
		ntStatus = IoCreateFile(
			&hFind,
			FILE_LIST_DIRECTORY | SYNCHRONIZE | FILE_ANY_ACCESS,
			&oa,
			&ioStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,	//FILE_OPEN
			FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
			NULL,
			0,
			CreateFileTypeNone,
			NULL,
			IO_NO_PARAMETER_CHECKING);
		RtlFreeUnicodeString(&ustrFolder);
		if (ntStatus == 0 && hFind != INVALID_HANDLE_VALUE)
		{
			ntStatus = ZwQueryDirectoryFile(
				hFind, // File Handle
				NULL, // Event
				NULL, // Apc routine
				NULL, // Apc context
				&ioStatus, // IoStatusBlock
				pDir, // FileInformation
				uLength, // Length
				FileBothDirectoryInformation, // FileInformationClass
				TRUE, // ReturnSingleEntry
				NULL, // FileName
				FALSE //RestartScan
			);
			if (ntStatus != 0)
			{
				ZwClose(hFind);
				hFind = INVALID_HANDLE_VALUE;
			}
		}
	}
	return hFind;
	VMProtectEnd();
}

BOOLEAN MyFindNextFile(HANDLE hFind, PFILE_BOTH_DIR_INFORMATION pDir, ULONG uLength)
{
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS ntStatus;
	ntStatus = ZwQueryDirectoryFile(
		hFind, // File Handle
		NULL, // Event
		NULL, // Apc routine
		NULL, // Apc context
		&ioStatus, // IoStatusBlock
		pDir, // FileInformation
		uLength, // Length
		FileBothDirectoryInformation, // FileInformationClass
		FALSE, // ReturnSingleEntry
		NULL, // FileName
		FALSE //RestartScan
	);
	if (ntStatus == 0)
		return TRUE;
	else
		return FALSE;
}

ULONG SearchForDrivers(LPSTR lpPath, char *FileArray)	//, PDIR_INFO pDirInfo
{
	VMProtectBeginUltra("SearchForDrivers");
	ULONG muFileCount = 0;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	PFILE_BOTH_DIR_INFORMATION pDir;
	char *strBuffer = NULL, *lpTmp = NULL;
	char strFileName[255 * 2];
	UNICODE_STRING n;
	UNICODE_STRING UniTemp;
	ANSI_STRING AnsiTemp;
	char *p;
	char AnsiConvTemp[256] = { 0 };

	ULONG uLength = MAX_PATH2 * 2 + sizeof(FILE_BOTH_DIR_INFORMATION);
	strBuffer = (PCHAR)RtlAllocateMemoryV(uLength);
	pDir = (PFILE_BOTH_DIR_INFORMATION)strBuffer;
	hFind = MyFindFirstFile(lpPath, pDir, uLength);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		RtlFreeMemoryV(strBuffer);
		uLength = (MAX_PATH2 * 2 + sizeof(FILE_BOTH_DIR_INFORMATION)) * 0x2000;
		strBuffer = (PCHAR)RtlAllocateMemoryV(uLength);
		pDir = (PFILE_BOTH_DIR_INFORMATION)strBuffer;
		if (MyFindNextFile(hFind, pDir, uLength))
		{
			while (TRUE)
			{
				memset(strFileName, 0, 255 * 2);
				memcpy(strFileName, pDir->FileName, pDir->FileNameLength);
				if (strcmp(strFileName, "..") != 0 && strcmp(strFileName, ".") != 0)
				{
					if (pDir->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						//DbgPrint("[目录]%S\n", strFileName);
					}
					else
					{
						UniTemp.Length = pDir->FileNameLength;
						UniTemp.MaximumLength = 600;
						UniTemp.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, UniTemp.MaximumLength, BB_POOL_TAG);
						RtlCopyMemory(UniTemp.Buffer, pDir->FileName, pDir->FileNameLength);

						RtlUnicodeStringToAnsiString(&AnsiTemp, &UniTemp, TRUE);
						strcpy(AnsiConvTemp, AnsiTemp.Buffer);
						RtlFreeAnsiString(&AnsiTemp);
						RtlFreeUnicodeString(&UniTemp);

						if (InStr(AnsiConvTemp, ".sys") && !InStr(AnsiConvTemp, DriverAnsiName))
						{
							//DPRINT("Driver Found %s\r\n", AnsiConvTemp);
							strcpy(FileArray + (256 * muFileCount), AnsiConvTemp);
							muFileCount++;
						}

						//DPRINT("%S\r\n", strFileName);
						//DbgPrint("[文件]%S\n", strFileName);
						
					}
					
				}
				if (pDir->NextEntryOffset == 0) break;
				pDir = (PFILE_BOTH_DIR_INFORMATION)((char *)pDir + pDir->NextEntryOffset);
			}
			RtlFreeMemoryV(strBuffer);
		}
		ZwClose(hFind);
	}

	DPRINT("Total Files %d\r\n", muFileCount);
	return muFileCount;
	VMProtectEnd();
}

int CheckIfPIDRunning(HANDLE pid)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	int running = 0;

	DPRINT("Checking process id %d\r\n", pid);
	status = PsLookupProcessByProcessId_D((HANDLE)pid, &pProcess);
	if (NT_SUCCESS(status))
	{
		DPRINT("process id %d is running\r\n", pid);
		running = 1;
	}
	else
	{
		DPRINT("process id %d is not running\r\n", pid);
	}

	if (pProcess)
		ObDereferenceObject(pProcess);

	return running;
}

int AKTerminateProcess(HANDLE pid)
{
	VMProtectBegin("AKTerminateProcess");
	NTSTATUS status = STATUS_SUCCESS;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T length = 0;
	ULONG_PTR memptr = 0;
	PMAP_ENTRY pEntry = NULL;
	unsigned char *p = NULL;
	KAPC_STATE apc;
	PEPROCESS pProcess = NULL;
	CLIENT_ID client_id;
	OBJECT_ATTRIBUTES objAttr;
	HANDLE hProcess;


	if (!NT_SUCCESS(PsLookupProcessByProcessId_D(pid, &pProcess)))
	{
		if (pProcess)
			ObDereferenceObject(pProcess);

		DPRINT("AKDriver: nable to resolve PID %d to PEPROCESS\n", pid);
		return 0;
	}

	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	client_id.UniqueProcess = pid;
	client_id.UniqueThread = (HANDLE)0;
	status = ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &objAttr, &client_id);
	if (status != STATUS_SUCCESS)
	{
		if (pProcess)
			ObDereferenceObject(pProcess);

		DPRINT("AKDriver: Auth Failed, Unable to open process id %d status 0x%X\n", pid, status);
		return 0;
	}

	ZwTerminateProcess(hProcess, 0);
	ZwClose(hProcess);

	if (pProcess)
		ObDereferenceObject(pProcess);

	VMProtectEnd();
}