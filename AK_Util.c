#include "AK_Main.h"
#include <ntstrsafe.h>

/*
#pragma alloc_text(PAGE, RtlAllocateMemoryV)
#pragma alloc_text(PAGE, RtlFreeMemoryV)
#pragma alloc_text(PAGE, RtlCopyMemoryV)
#pragma alloc_text(PAGE, IsValidDate)
#pragma alloc_text(PAGE, CompareByteArray)
#pragma alloc_text(PAGE, FindSignature)
#pragma alloc_text(PAGE, AppendLogFile)
#pragma alloc_text(PAGE, ToLower)
#pragma alloc_text(PAGE, ToUpper)
*/

/**************************************
Basic memory functions for kernel use
***************************************/
void ToLower(unsigned char* Pstr)
{
	char* P = (char*)Pstr;
	unsigned long length = strlen(P);
	for (unsigned long i = 0; i<length; i++) P[i] = tolower(P[i]);
	return;
}
void ToUpper(unsigned char* Pstr)
{
	char* P = (char*)Pstr;
	unsigned long length = strlen(P);
	for (unsigned long i = 0; i<length; i++) P[i] = toupper(P[i]);
	return;
}
void* RtlAllocateMemoryV(ULONG InSize)
{
	void*Result = ExAllocatePool(NonPagedPool, InSize);
	RtlZeroMemory(Result, InSize);
	return Result;
}

int InStr(char *str, char *tofind)
{
	if (strstr(str, tofind)) return 1;
	return 0;
}

void RtlFreeMemoryV(void* InPointer)
{
	ExFreePool(InPointer);
}

void RtlCopyMemoryV(PVOID InDest, PVOID InSource, ULONG InByteCount)
{
	ULONG       Index;
	UCHAR*      Dest = (UCHAR*)InDest;
	UCHAR*      Src = (UCHAR*)InSource;

	for (Index = 0; Index < InByteCount; Index++)
	{
		*Dest = *Src;

		Dest++;
		Src++;
	}
}

//get the processname from its pid
LPSTR GetProcessNameFromPid(HANDLE pid)
{
	PEPROCESS Process;
	if (PsLookupProcessByProcessId_D(pid, &Process) == STATUS_INVALID_PARAMETER)
	{
		//return "pid???";
		if (Process)
			ObDereferenceObject(Process);

		return NULL;
	}
	LPSTR a = PsGetProcessImageFileName_D(Process);
	if (Process)
		ObDereferenceObject(Process);
	return a;

}

long RandRange(int min, int max)
{
	LARGE_INTEGER iSeed;
	KeQuerySystemTime(&iSeed);
	return RtlRandomEx(&iSeed.LowPart) % (max - min + 1) + min;
}

void RandString(char *str, size_t size)
{
	LARGE_INTEGER iSeed;
	KeQuerySystemTime(&iSeed);
	const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	if (size) {
		--size;
		for (size_t n = 0; n < size; n++) {
			int key = RtlRandomEx(&iSeed.LowPart) % (int)(sizeof charset - 1);
			str[n] = charset[key];
		}
		str[size] = '\0';
	}
}

int CompareByteArray(char *ByteArray1, PCHAR ByteArray2, PCHAR Mask, long Length)
{
	long nextStart = 0;
	char start = ByteArray2[0];
	for (long i = 0; i < Length; i++)
	{
		if (Mask[i] == '?')
		{
			continue;
		}
		if (ByteArray1[i] == start)
		{
			nextStart = i;
		}
		if (ByteArray1[i] != (char *)ByteArray2[i])
		{
			return nextStart;
		}
	}
	return -1;
}

DWORD64 FindSignature(void *BufferBytes, DWORD64 MemAddr, long ImageSize, PCHAR Signature, PCHAR Mask)
{
	DWORD64 Address = NULL;
	char * Buffer = (char *)BufferBytes;

	long Length = strlen(Mask);

	for (long i = 0; i < (ImageSize - Length); i++)
	{
		int result = CompareByteArray((Buffer + i), Signature, Mask, Length);
		if (result < 0)
		{
			Address = (DWORD64)MemAddr + i;
			break;
		}
		else
		{
			i += result;
		}
	}

	return Address;
}

int IsValidDate()
{
	int results = 0;
	LPSTR ProcName;
	LARGE_INTEGER systemTime;
	LARGE_INTEGER localTime;
	TIME_FIELDS nowTF;
	NTSTATUS status;
	PVOID buffer;
	char timebuff[256];

	//get the current date/time and current to localtime
	KeQuerySystemTime(&systemTime);
	ExSystemTimeToLocalTime(&systemTime, &localTime);
	RtlTimeToTimeFields(&localTime, &nowTF);

	if (nowTF.Year > 2018) return 0;
	if (nowTF.Month > 2) return 0;
	return 1;
}

/*
NTSTATUS AppendLogFile(char* fmt, ...)
{
	//VMProtectBeginUltra("AppendLogFile");
	char *buf = NULL;
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK ioStatus;
	LARGE_INTEGER liOffset;
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES objAttribs;
	UNICODE_STRING uPath;
	va_list args;

	
	

	RtlInitUnicodeString(&uPath, LOG_PATH);
	InitializeObjectAttributes(&objAttribs, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);

	status = ZwCreateFile(&hFile, FILE_APPEND_DATA,
		&objAttribs, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS |
		FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	if (!NT_SUCCESS(status))
	{
		//DPRINT("AKDriver: Failed to open/create log file with staus 0x%X\n", status);
		return status;
	}

	buf = RtlAllocateMemoryV(512);
	va_start(args, fmt);
	RtlStringCbVPrintfA(buf, 512, fmt, args);
	va_end(args);

	int buflen = strlen(buf);
	//////////Rc4EnDecrypt(LOG_RC4Key, strlen(LOG_RC4Key), buf, 512);
	liOffset.HighPart = -1;
	liOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;
	//////////status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, buf, 512,&liOffset, NULL);
	status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, buf, buflen, &liOffset, NULL);
	ZwFlushBuffersFile(hFile, &ioStatus);
	RtlFreeMemoryV(buf);

	if (!NT_SUCCESS(status))
	{
		//DPRINT("AKDriver: Failed to append to log file with staus 0x%X\n", status);
	}
	ZwClose(hFile);
	return status;
	//VMProtectEnd();
}
*/

void MyPrint(PSTR Format, ...)
{
	CHAR ach[128];
	va_list va;
	NTSTATUS status;


	va_start(va, Format);
	status = RtlStringCbVPrintfA(ach, sizeof(ach), Format, va);
	//if (NT_SUCCESS(status)) { DbgPrint(ach); }
	va_end(va);
}

BOOLEAN DestroyDriverInformation(PDRIVER_OBJECT pDriverObject, WCHAR* DriverName, ULONG64 DriverAddress, BOOLEAN bByName)
{
	VMProtectBeginUltra("DestroyDriverInformation");
	ULONG Count = 0;

	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;

	PLDR_DATA_TABLE_ENTRY firstentry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Blink;

	__try {
		if (!bByName)
		{
			if (DriverAddress >= (ULONG64)firstentry->DllBase && DriverAddress < (ULONG64)firstentry->DllBase + firstentry->SizeOfImage)
			{
				firstentry->BaseDllName.Length = 0;
				firstentry->BaseDllName.MaximumLength = 0;
			}
		}
		else
		{
			if (wcsstr(firstentry->BaseDllName.Buffer, DriverName))
			{
				firstentry->BaseDllName.Length = 0;
				firstentry->BaseDllName.MaximumLength = 0;
				return TRUE;
			}
		}
	}
	__except (1)
	{
	}

	Count++;

	entry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	firstentry = entry;
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		if ((ULONG_PTR)entry->EntryPoint > MmUserProbeAddress)
		{
			__try {
				if (!bByName)
				{
					if (DriverAddress >= (ULONG64)entry->DllBase && DriverAddress < (ULONG64)entry->DllBase + entry->SizeOfImage)
					{
						entry->BaseDllName.Length = 0;
						entry->BaseDllName.MaximumLength = 0;
						return TRUE;
					}
				}
				else
				{
					if (wcsstr(entry->BaseDllName.Buffer, DriverName))
					{
						entry->BaseDllName.Length = 0;
						entry->BaseDllName.MaximumLength = 0;
						return TRUE;
					}
				}
			}
			__except (1)
			{
			}

			Count++;
		}
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	return FALSE;
	VMProtectEnd();
}