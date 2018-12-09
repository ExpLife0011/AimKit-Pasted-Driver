#include "AK_Main.h"

/*
#pragma alloc_text(PAGE, FindPspCreateProcessNotifyRoutine)
#pragma alloc_text(PAGE, EnumRemoveCreateProcessNotify)
#pragma alloc_text(PAGE, RestoreCreateProcessNotify)
#pragma alloc_text(PAGE, ClearCreateProcessNotify)
*/

ULONG64 NotifyProcRoutines[64];
int TotalProcNotifySaved = 0;

ULONG64 FindPspCreateProcessNotifyRoutine()
{
	LONG			OffsetAddr = 0;
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;

	RtlInitUnicodeString(&unstrFunc, L"PsSetCreateProcessNotifyRoutine");
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);

	memcpy(&OffsetAddr, (PUCHAR)pCheckArea + 4, 4);
	pCheckArea = (pCheckArea + 3) + 5 + OffsetAddr;

	for (i = pCheckArea; i<pCheckArea + 0xff; i++)
	{
		if (*(PUCHAR)i == 0x4c && *(PUCHAR)(i + 1) == 0x8d && *(PUCHAR)(i + 2) == 0x35)	//lea r14,xxxx
		{
			LONG OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			return OffsetAddr + 7 + i;
		}
	}
	return 0;
}

void EnumRemoveCreateProcessNotify()
{
	int i = 0;
	BOOLEAN b;
	ULONG64	NotifyAddr = 0, MagicPtr = 0;


	TotalProcNotifySaved = 0;
	ClearCreateProcessNotify();

	ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
	if (!PspCreateProcessNotifyRoutine)
		return;
	for (i = 0; i<64; i++)
	{
		MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
		NotifyAddr = *(PULONG64)(MagicPtr);
		if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
		{
			NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);

			NotifyProcRoutines[TotalProcNotifySaved] = NotifyAddr;
			TotalProcNotifySaved++;
			PsSetCreateProcessNotifyRoutine(NotifyAddr,TRUE);
		}
	}
}


void RestoreCreateProcessNotify()
{
	int i;
	for (i = 0; i < TotalProcNotifySaved; i++)
	{
		if (MmIsAddressValid((PVOID)NotifyProcRoutines[i]) && NotifyProcRoutines[i] != 0)
		{
			PsSetCreateProcessNotifyRoutine(NotifyProcRoutines[i],FALSE);
		}

		NotifyProcRoutines[i] = 0;
	}
	TotalProcNotifySaved = 0;
}

void ClearCreateProcessNotify()
{
	int i;
	for (i = 0; i < 64; i++)
	{
		NotifyProcRoutines[i] = 0;
	}
}