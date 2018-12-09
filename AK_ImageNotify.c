#include "AK_Main.h"

/*
#pragma alloc_text(PAGE, FindPspLoadImageNotifyRoutine)
#pragma alloc_text(PAGE, EnumRemoveLoadImageNotify)
#pragma alloc_text(PAGE, RestoreLoadImageNotify)
#pragma alloc_text(PAGE, ClearImageNotifyArray)
*/

ULONG64 NotifyRoutines[8];
int TotalNotifySaved = 0;

ULONG64 FindPspLoadImageNotifyRoutine()
{
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	RtlInitUnicodeString(&unstrFunc, VMProtectDecryptStringW(L"PsSetLoadImageNotifyRoutine"));
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	for (i = pCheckArea; i<pCheckArea + 0xff; i++)
	{
		if (*(PUCHAR)i == 0x48 && *(PUCHAR)(i + 1) == 0x8d && *(PUCHAR)(i + 2) == 0x0d)	//lea rcx,xxxx
		{
			LONG OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			return OffsetAddr + 7 + i;
		}
	}
	return 0;
}

void EnumRemoveLoadImageNotify()
{
	int i = 0;
	BOOLEAN b;
	ULONG64	NotifyAddr = 0, MagicPtr = 0;

	TotalNotifySaved = 0;
	ClearImageNotifyArray();

	ULONG64	PspLoadImageNotifyRoutine = FindPspLoadImageNotifyRoutine();
	if (!PspLoadImageNotifyRoutine)
		return;
	for (i = 0; i<8; i++)
	{
		MagicPtr = PspLoadImageNotifyRoutine + i * 8;
		NotifyAddr = *(PULONG64)(MagicPtr);
		if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
		{
			NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
			
			NotifyRoutines[TotalNotifySaved] = NotifyAddr;
			AKDPRINT("removing 0x%llx\r\n", NotifyRoutines[TotalNotifySaved]);
			TotalNotifySaved++;
			PsRemoveLoadImageNotifyRoutine(NotifyAddr);
		}
	}
}

void RestoreLoadImageNotify()
{
	int i;
	for (i = 0; i < TotalNotifySaved; i++)
	{
		//if (MmIsAddressValid((PVOID)NotifyRoutines[i]) && NotifyRoutines[i] != 0)
		if (NotifyRoutines[i] != 0)
		{
			AKDPRINT("restoring 0x%llx\r\n", NotifyRoutines[i]);
			PsSetLoadImageNotifyRoutine(NotifyRoutines[i]);
		}
	}
	ClearImageNotifyArray();
}

void ClearImageNotifyArray()
{
	int i;
	for (i = 0; i < 8; i++)
	{
		NotifyRoutines[i] = 0;
	}
	TotalNotifySaved = 0;
}