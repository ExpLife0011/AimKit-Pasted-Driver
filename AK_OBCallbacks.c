#include "AK_Main.h"

/*
#pragma alloc_text(PAGE, RegisterCallbackFunction)
#pragma alloc_text(PAGE, FreeProcFilter)
#pragma alloc_text(PAGE, RegisterPostCallbackFunction)

#pragma alloc_text(PAGE, OBIsPidAuthed)
#pragma alloc_text(PAGE, OBAddPid)
#pragma alloc_text(PAGE, OBRemovePid)
#pragma alloc_text(PAGE, ClearOBAuthPids)
#pragma alloc_text(PAGE, DoesOBPidExist)
*/

PVOID _CallBacks_Handle = NULL;
PVOID _Post_CallBacks_Handle = NULL;

//store process information if request if valid
char GHProcessName[256];
int GHProcessSet = 0;
int GHPid = 0;

int AuthedPids[5];




// Pre callback
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(IN  PVOID RegistrationContext, IN  POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	LPSTR ProcName;
	ACCESS_MASK desired = 0;
	PEPROCESS CallingProcess = PsGetCurrentProcess_D();

	//this is the process id of the process talking to the driver
	int CallingProcessID = (int)PsGetCurrentProcessId_D();

	//this is the process id of the process we want access to,
	int DestinProcessID = (int)PsGetProcessId((PEPROCESS)OperationInformation->Object);
	ProcName = GetProcessNameFromPid(PsGetProcessId((PEPROCESS)OperationInformation->Object));
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (GHProcessSet)
	{
		//deny all access if the calling process id is not ours and it wants to access our process


		if (DestinProcessID == GHPid && CallingProcessID != GHPid)
		{
			if (!InStr(ProcName, VMProtectDecryptStringA("RustClient")) && !InStr(ProcName, VMProtectDecryptStringA("EasyAnti")))
			{
				if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				{
					if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
					{
						OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
					}
					if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
					{
						OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
					}
					if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & ~PROCESS_VM_READ) == PROCESS_VM_READ)
					{
						OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
					}
					if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
					{
						OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
					}
				}
			}
			return OB_PREOP_SUCCESS;
		}
		

		//if pid is authed give access to any process that's not ours(unless our pid asking for access, which we check above)
		
		if (OBIsPidAuthed(CallingProcessID) || CallingProcessID == GHPid)
		{
			if (DestinProcessID == GHPid)
			{
				if (OB_OPERATION_HANDLE_CREATE == OperationInformation->Operation)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
				}
				else if (OB_OPERATION_HANDLE_DUPLICATE == OperationInformation->Operation)
				{
					OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
				}
				return OB_PREOP_SUCCESS;
			}
		}
		


	}
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ObjectPreCallback ----> Process Name [%s] \n", ProcName);
	return OB_PREOP_SUCCESS;
}

//post callback
VOID ObjectPostCallback(IN  PVOID RegistrationContext, IN  POB_POST_OPERATION_INFORMATION OperationInformation)
{
	//UNREFERENCED_PARAMETER(RegistrationContext);
	//UNREFERENCED_PARAMETER(OperationInformation);
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PostProcCreateRoutine. \n");
}


//important thing is the altitude allows us to bypass others
NTSTATUS RegisterCallbackFunction()
{
	VMProtectBeginUltra("RegisterCallbackFunction");
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING Altitude;
	USHORT filterVersion = ObGetFilterVersion();
	USHORT registrationCount = 1;
	OB_OPERATION_REGISTRATION RegisterOperation;
	OB_CALLBACK_REGISTRATION RegisterCallBack;
	REG_CONTEXT RegistrationContext;
	memset(&RegisterOperation, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&RegisterCallBack, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&RegistrationContext, 0, sizeof(REG_CONTEXT));
	RegistrationContext.ulIndex = 1;
	RegistrationContext.Version = 120;
	if (filterVersion == OB_FLT_REGISTRATION_VERSION) {

		RegisterOperation.ObjectType = PsProcessType;
		RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE;
		RegisterOperation.PreOperation = ObjectPreCallback;
		RegisterOperation.PostOperation = ObjectPostCallback;
		RegisterCallBack.Version = OB_FLT_REGISTRATION_VERSION;
		RegisterCallBack.OperationRegistrationCount = registrationCount;
		RtlInitUnicodeString(&Altitude, VMProtectDecryptStringW(L"428997"));
		RegisterCallBack.Altitude = Altitude;
		RegisterCallBack.RegistrationContext = &RegistrationContext;
		RegisterCallBack.OperationRegistration = &RegisterOperation;


		ntStatus = ObRegisterCallbacks(&RegisterCallBack, (PVOID *)&_CallBacks_Handle);
	}
	return ntStatus;
	VMProtectEnd();
}

//important thing is the altitude allows us to bypass others
NTSTATUS RegisterPostCallbackFunction()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING Altitude;
	USHORT filterVersion = ObGetFilterVersion();
	USHORT registrationCount = 1;
	OB_OPERATION_REGISTRATION RegisterOperation;
	OB_CALLBACK_REGISTRATION RegisterCallBack;
	REG_CONTEXT RegistrationContext;
	memset(&RegisterOperation, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&RegisterCallBack, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&RegistrationContext, 0, sizeof(REG_CONTEXT));
	RegistrationContext.ulIndex = 1;
	RegistrationContext.Version = 120;
	if (filterVersion == OB_FLT_REGISTRATION_VERSION) {

		RegisterOperation.ObjectType = PsProcessType;
		RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE;
		RegisterOperation.PreOperation = ObjectPreCallback;
		RegisterOperation.PostOperation = ObjectPostCallback;
		RegisterCallBack.Version = OB_FLT_REGISTRATION_VERSION;
		RegisterCallBack.OperationRegistrationCount = registrationCount;
		RtlInitUnicodeString(&Altitude, VMProtectDecryptStringW(L"40014"));
		RegisterCallBack.Altitude = Altitude;
		RegisterCallBack.RegistrationContext = &RegistrationContext;
		RegisterCallBack.OperationRegistration = &RegisterOperation;

		ntStatus = ObRegisterCallbacks(&RegisterCallBack, (PVOID *)&_Post_CallBacks_Handle);
	}

	return ntStatus;
}

//free up things on unload
NTSTATUS FreeProcFilter()
{
	if (NULL != _CallBacks_Handle)
	{
		ObUnRegisterCallbacks(_CallBacks_Handle);
		_CallBacks_Handle = NULL;
	}

	if (NULL != _Post_CallBacks_Handle)
	{
		ObUnRegisterCallbacks(_Post_CallBacks_Handle);
		_Post_CallBacks_Handle = 0;
	}

	ObsRunning = 0;
	return STATUS_SUCCESS;
}


void ClearOBAuthPids()
{
	int i;
	for (i = 0; i < 5; i++)
	{
		AuthedPids[i] = 0;
	}
}


int OBIsPidAuthed(int pid)
{
	int i;
	if (pid == 0) return 0;
	for (i = 0; i < 5; i++)
	{
		if (AuthedPids[i] == pid) return 1;
	}
	return 0;
}

int OBAddPid(int pid)
{
	int i;
	if (pid == 0) return 0;
	if (DoesOBPidExist(pid)) return 0;
	for (i = 0; i < 5; i++)
	{
		if (AuthedPids[i] == 0)
		{
			AuthedPids[i] = pid;
			return 1;
		}
	}
	return 0;
}

int OBRemovePid(int pid)
{
	int i;
	if (pid == 0) return 0;
	for (i = 0; i < 5; i++)
	{
		if (AuthedPids[i] == pid)
		{
			AuthedPids[i] = 0;
			return 1;
		}
	}
	return 0;
}

int DoesOBPidExist(int pid)
{
	int i;
	if (pid == 0) return 0;
	for (i = 0; i < 5; i++)
	{
		if (AuthedPids[i] == pid)
		{
			return 1;
		}
	}
	return 0;
}