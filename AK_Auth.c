#include "AK_Main.h"
#include "Remap.h"
#include "Utils.h"
/*
#pragma alloc_text(PAGE, FoundSigAuthProcess)
#pragma alloc_text(PAGE, isRequestValid)
#pragma alloc_text(PAGE, IsCallingPidAuthed)
#pragma alloc_text(PAGE, IsUnloadAuthed)
*/

//rc4 crypt key
//char RequestCryptKey[] = "94859505904939054905355241";

//request sha256 hash slt
//char GHSalt[] = "Vti494245hplmTbth3339Tb7";

int GH_SigAuthed = 0;

int GH_AuthDriverUnload = 0;

int FoundSigAuthProcess(int pid)
{
	VMProtectBegin("FoundSigAuthProcess");
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

	GH_SigAuthed = 0;
	if (PsLookupProcessByProcessId_D(pid, &pProcess) == STATUS_INVALID_PARAMETER)
	{
		if (pProcess)
			ObDereferenceObject(pProcess);

		DPRINT("AKDriver: Auth Failed, unable to resolve PID %d to PEPROCESS\n", pid);
		return 0;
	}

	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	client_id.UniqueProcess = pid;
	client_id.UniqueThread = (HANDLE)0;
	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &client_id);
	if(status!= STATUS_SUCCESS)
	{
		if (pProcess)
			ObDereferenceObject(pProcess);

		DPRINT("AKDriver: Auth Failed, Unable to open process id %d status 0x%X\n", pid, status);
		return 0;
	}
	//KeStackAttachProcess(pProcess, &apc);

	char *SigHex = (char*)RtlAllocateMemoryV(300);
	//strcpy(SigHex, (char *)VMProtectDecryptStringA("\x48\x89\x5C\x24\x08\x41\x8B\xD8\x4C\x8B\xD2\x4C\x8B\xD9\x49\x83\xC9\xFF\x49\xFF\xC1\x42\x80\x3C\x09\x00\x75\xF6\x45\x33\xC0\x85\xDB\x7E\x2C\x0F\x1F\x40\x00\x66\x0F\x1F\x84\x00\x00\x00\x00\x00"));
	//strcpy(SigHex, (char *)VMProtectDecryptStringA("\x48\x89\x5C\x24\x08\x41\x8B\xD8\x4C\x8B\xD2\x4C\x8B\xD9\x49\x83\xC9\xFF\x49\xFF\xC1\x42\x80\x3C\x09\x11\x75\xF6\x45\x33\xC0\x85\xDB\x7E\x2C\x0F\x1F\x40"));

	char *SigMask = (char*)RtlAllocateMemoryV(300);
	strcpy(SigMask, (char *)VMProtectDecryptStringA("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));

	for (memptr = (ULONG_PTR)MM_LOWEST_USER_ADDRESS; memptr < (ULONG_PTR)MM_HIGHEST_USER_ADDRESS; memptr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize)
	{
		status = ZwQueryVirtualMemory(hProcess, (PVOID)memptr, MemoryBasicInformation, &mbi, sizeof(mbi), &length);
		if (!NT_SUCCESS(status))
		{
			DPRINT("AKDriver: %s: ZwQueryVirtualMemory for address 0x%p failed, status 0x%X\n", __FUNCTION__, memptr, status);
			if (pProcess)
				ObDereferenceObject(pProcess);
			ZwClose(hProcess);

			return status;
		}

		if ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_READ))
		{

			__try {
				ProbeForRead((PVOID)memptr, mbi.RegionSize, 1);
				//DPRINT("AKDriver: Searching Page Size %d.\n", mbi.RegionSize);
				char *buf = RtlAllocateMemoryV(mbi.RegionSize);
				RtlCopyMemory(buf, (PVOID)memptr, mbi.RegionSize);

				DWORD64 SAddress = (DWORD64)memptr;
				if (FindSignature(buf, SAddress, mbi.RegionSize, "\x48\x89\x5C\x24\x08\x41\x8B\xD8\x4C\x8B\xD2\x4C\x8B\xD9\x49\x83\xC9\xFF\x49\xFF\xC1\x42\x80\x3C\x09\x00\x75\xF6\x45\x33\xC0\x85\xDB\x7E\x2C\x0F\x1F\x40\x00\x66\x0F\x1F\x84\x00\x00\x00\x00\x00", SigMask) != NULL)
				{
					DPRINT("AKDriver: Found -> Authed %d.\n", mbi.RegionSize);
					GH_SigAuthed = 1;
					RtlFreeMemoryV(buf);
					break;
				}
				RtlFreeMemoryV(buf);

			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DPRINT("AKDriver: Address 0x%x isn't accessible.\n", memptr);
			}
			

		}

	}
	RtlFreeMemoryV(SigHex);
	RtlFreeMemoryV(SigMask);
	ZwClose(hProcess);

	if (pProcess)
		ObDereferenceObject(pProcess);
	//KeUnstackDetachProcess(&apc);
	return GH_SigAuthed;
	VMProtectEnd();
}




//this verifies the request sent from a process for access/protection is valid
int isRequestValid(char *idata, int idatalen)
{
	VMProtectBegin("isRequestValid");
	int results = 0;
	LPSTR ProcName;
	LARGE_INTEGER systemTime;
	LARGE_INTEGER localTime;
	TIME_FIELDS nowTF;
	NTSTATUS status;
	PVOID buffer;
	char timebuff[256];

	//decrypt the request data sent to our driver
	//RequestCryptKey
	Rc4EnDecrypt(VMProtectDecryptStringA("94859505904939054905355241"), strlen(VMProtectDecryptStringA("94859505904939054905355241")), idata, idatalen);

	//get the current date/time and current to localtime
	KeQuerySystemTime(&systemTime);
	ExSystemTimeToLocalTime(&systemTime, &localTime);
	RtlTimeToTimeFields(&localTime, &nowTF);

	//format the calling process id with the current day, month, year
	int callingpid = (int)PsGetCurrentProcessId_D();
	sprintf(timebuff, VMProtectDecryptStringA("%d%d.%02d.%04d"), callingpid, nowTF.Day, nowTF.Month, nowTF.Year);

	//hash with our salt
	//char GHSalt[] = "Vti494245hplmTbth3339Tb7";

	char* ihash = Sha256HashWithSalt(timebuff, VMProtectDecryptStringA("Vti494245hplmTbth3339Tb7"));

	//compare against the hash the process talking to our drive sent us
	if (strcmp(ihash, idata) == 0)
	{
		//store the process information in variables to bypass other obcallbacks set by other drivers and to provide protection by our driver
		GHProcessSet = 1;
		GHPid = (int)PsGetCurrentProcessId_D();

		ProcName = GetProcessNameFromPid(GHPid);
		char *tmphash = Sha256HashWithSalt(ProcName, VMProtectDecryptStringA("Vti494245hplmTbth3339Tb7"));
		strcpy(GHProcessName, tmphash);
		RtlFreeMemoryV(tmphash);
		results = 1;
	}
	RtlFreeMemoryV(ihash);
	return results;
	VMProtectEnd();
}

//check if the calling process is authorized
int IsCallingPidAuthed()
{
	if (!GHProcessSet) return 0;
	if (!GH_SigAuthed)  return 0;
	int currentpid = (int)PsGetCurrentProcessId_D();
	if (GHPid != currentpid) return 0;
	return 1;
}

//check if driver is permitted to beunloaded
int IsUnloadAuthed()
{
	if (!GHProcessSet) return 0;
	if (!GH_SigAuthed)  return 0;
	if (!GH_AuthDriverUnload) return 0;
	return 1;
}
