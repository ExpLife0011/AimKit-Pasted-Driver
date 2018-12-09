#include "AK_Main.h"

/*
#pragma alloc_text(PAGE, FindPspCreateThreadNotifyRoutine)
#pragma alloc_text(PAGE, EnumRemoveCreateThreadNotify)
#pragma alloc_text(PAGE, RestoreThreadNotify)
#pragma alloc_text(PAGE, ClearThreadNotify)
*/

ULONG64 NotifyThreadRoutines[64];
int TotalThreadNotifySaved = 0;


ULONG64 FindPspCreateThreadNotifyRoutine()
{
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	RtlInitUnicodeString(&unstrFunc, L"PsSetCreateThreadNotifyRoutine");
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

void EnumRemoveCreateThreadNotify()
{
	int i = 0;
	BOOLEAN b;
	ULONG64	NotifyAddr = 0, MagicPtr = 0;

	TotalThreadNotifySaved = 0;
	ClearThreadNotify();

	ULONG64	PspCreateThreadNotifyRoutine = FindPspCreateThreadNotifyRoutine();
	if (!PspCreateThreadNotifyRoutine)
		return;
	for (i = 0; i<64; i++)
	{
		MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
		NotifyAddr = *(PULONG64)(MagicPtr);
		if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
		{
			NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);

			NotifyThreadRoutines[TotalThreadNotifySaved] = NotifyAddr;
			TotalThreadNotifySaved++;
			PsRemoveCreateThreadNotifyRoutine(NotifyAddr);

		}
	}
}


void RestoreThreadNotify()
{
	int i;
	for (i = 0; i < TotalThreadNotifySaved; i++)
	{
		if (MmIsAddressValid((PVOID)NotifyThreadRoutines[i]) && NotifyThreadRoutines[i] != 0)
		{
			PsSetCreateThreadNotifyRoutine(NotifyThreadRoutines[i]);
		}

		NotifyThreadRoutines[i] = 0;
	}
	TotalThreadNotifySaved = 0;
}

void ClearThreadNotify()
{
	int i;
	for (i = 0; i < 64; i++)
	{
		NotifyThreadRoutines[i] = 0;
	}
	TotalThreadNotifySaved = 0;
}