#pragma once
#include "AK_Main.h"


OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
	IN  PVOID RegistrationContext,
	IN  POB_PRE_OPERATION_INFORMATION OperationInformation
);

VOID ObjectPostCallback(
	IN  PVOID RegistrationContext,
	IN  POB_POST_OPERATION_INFORMATION OperationInformation
);

NTSTATUS RegisterCallbackFunction();
NTSTATUS FreeProcFilter();
NTSTATUS RegisterPostCallbackFunction();

int OBIsPidAuthed(int pid);
int OBAddPid(int pid);
int OBRemovePid(int pid);
void ClearOBAuthPids();
int DoesOBPidExist(int pid);