#include "AK_Main.h"

PDRIVER_DISPATCH RealNetworkDeviceControl = NULL;
PDEVICE_OBJECT NetworkDevice = NULL;
PDRIVER_OBJECT NetworkDriver = NULL;
KSPIN_LOCK HashLock;
PFILE_OBJECT FileObject = NULL;
char NewMac[6];

int TotalNetAdapters = 0;
NetAdapters *pNetAdapters = NULL;


extern POBJECT_TYPE *IoDeviceObjectType;


NTSTATUS HookedNetworkDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION     irpStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG                  ctrlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	NTSTATUS               status;
	ULONG                  i = 0, j = 0;

	ULONG            controlCode = 0;
	PSRB_IO_CONTROL  srbControl;
	ULONG_PTR        buffer;
	PCDB                   cdb;
	KEVENT                 event;
	IO_STATUS_BLOCK        ioStatus;
	ULONG                  length;
	PIRP                   irp2;
	PUCHAR                 InputBuffer;
	PUCHAR                 OutputBuffer;
	ULONG                  InputBufferLength, OutputBufferLength;
	ULONG oid;
	char tmpdrivername[256] = { 0 };
	DbgPrint("HookedNetworkDeviceControl");
	InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	InputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	OutputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	//for certain repeat devices(like vmware) we need to lookup the saved driver name
	int index = FindNetworkAdapterByDevice(DeviceObject);
	if (index == -1)
	{
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DeviceObject->DriverObject->DriverSection;

		//convert drivername to ansi
		UniToAnsi(entry->BaseDllName.Buffer, &tmpdrivername);
		index = FindNetworkDeviceByDriverName(tmpdrivername);
		if (index == -1)
		{
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = NDIS_STATUS_SUCCESS;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return Irp->IoStatus.Status;
		}
	}

	if (ctrlCode == IOCTL_NDIS_QUERY_GLOBAL_STATS)
	{
		if (InputBufferLength < sizeof(oid))
		{
			return pNetAdapters[index].RealNetworkDeviceControl(DeviceObject, Irp);
		}
		memcpy(&oid, InputBuffer, sizeof(oid));

		
		if (oid == OID_802_3_PERMANENT_ADDRESS || oid == OID_802_3_CURRENT_ADDRESS)
		{
			PCHAR pOutputBuffer;
			pOutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress,NormalPagePriority);

			RtlZeroMemory(pOutputBuffer, OutputBufferLength);
			memcpy(pOutputBuffer, pNetAdapters[index].NewMac,6);

			Irp->IoStatus.Information = 6;
			Irp->IoStatus.Status = NDIS_STATUS_SUCCESS;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return Irp->IoStatus.Status;
		}
	}


	return  pNetAdapters[index].RealNetworkDeviceControl(DeviceObject, Irp);
}


void AddSpoofNetworkAdapter(SpoofAdapterRequest *req)
{
	DbgPrint("AddSpoofNetworkAdapter");
	if (DoesNetworkAdapterExist(req->GUIDA)) return;
	KIRQL			OldIrql;
	UNICODE_STRING udevicename;
	wchar_t frmbuff[256] = { 0 };
	char tmpdrivername[256] = { 0 };

	swprintf(frmbuff, L"\\device\\%ls", req->GUID);
	RtlInitUnicodeString(&udevicename, frmbuff);

	PDEVICE_OBJECT NetworkDevice = NULL;
	PFILE_OBJECT FileObject = NULL;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS ntStatus = IoGetDeviceObjectPointer(&udevicename, FILE_ALL_ACCESS, &FileObject, &NetworkDevice);
	if (ntStatus != STATUS_SUCCESS) return;

	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)NetworkDevice->DriverObject->DriverSection;
	
	//convert drivername to ansi
	UniToAnsi(entry->BaseDllName.Buffer, &tmpdrivername);

	//make sure we don't double hook the same driver as multiple devices can reference the same source
	if (DoesNetworkDriverExist(tmpdrivername))
	{
		ObDereferenceObject(FileObject);
		NetworkDevice = NULL;
		FileObject = NULL;
		return;
	}

	pNetAdapters[TotalNetAdapters].FileObject = FileObject;
	pNetAdapters[TotalNetAdapters].DeviceObject = NetworkDevice;

	strcpy(pNetAdapters[TotalNetAdapters].DriverName, tmpdrivername);
	wcscpy(pNetAdapters[TotalNetAdapters].GUID, req->GUID);
	strcpy(pNetAdapters[TotalNetAdapters].GUIDA, req->GUIDA);
	memcpy(pNetAdapters[TotalNetAdapters].NewMac, req->NewMac, 6);

	pNetAdapters[TotalNetAdapters].NetworkDriver = pNetAdapters[TotalNetAdapters].DeviceObject->DriverObject;
	pNetAdapters[TotalNetAdapters].RealNetworkDeviceControl = pNetAdapters[TotalNetAdapters].NetworkDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	InterlockedExchangePointer((volatile PVOID *)&pNetAdapters[TotalNetAdapters].NetworkDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL], HookedNetworkDeviceControl);

	pNetAdapters[TotalNetAdapters].Set = 1;
	TotalNetAdapters++;
}

void UniToAnsi(wchar_t *istr, char *ostr)
{
	ANSI_STRING AnsiKeyName;
	char ansibuff[256] = { 0 };
	UNICODE_STRING udevicename;
	RtlInitUnicodeString(&udevicename, istr);
	RtlUnicodeStringToAnsiString(&AnsiKeyName, &udevicename, TRUE);
	strcpy(ostr, AnsiKeyName.Buffer);
	RtlFreeAnsiString(&AnsiKeyName);
}


void RemUnSpoofAllAdapters()
{
	int i;
	for (i = 0; i < TotalNetAdapters; i++)
	{
		if (pNetAdapters[i].Set)
		{
			InterlockedExchangePointer((volatile PVOID *)&pNetAdapters[i].NetworkDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL], pNetAdapters[i].RealNetworkDeviceControl);
			
			//this deferences the deviceobject ptr as well
			ObDereferenceObject(pNetAdapters[i].FileObject);

			// Invalidate all pointers
			pNetAdapters[i].DeviceObject = NULL;
			pNetAdapters[i].NetworkDriver = NULL;
			pNetAdapters[i].RealNetworkDeviceControl = NULL;
			pNetAdapters[i].FileObject = NULL;
			pNetAdapters[i].Set = 0;
		}
	}
	TotalNetAdapters = 0;
}


int FindNetworkDeviceByDriverName(char *idriver)
{
	int i;
	for (i = 0; i < TotalNetAdapters; i++)
	{
		if (!pNetAdapters[i].Set) continue;
		if (strcmp(pNetAdapters[i].DriverName, idriver) == 0) return i;
	}
	return -1;
}
int DoesNetworkDriverExist(char *idriver)
{
	int i;
	for (i = 0; i < TotalNetAdapters; i++)
	{
		if (!pNetAdapters[i].Set) continue;
		if (strcmp(pNetAdapters[i].DriverName, idriver) == 0) return 1;
	}
	return 0;
}

int DoesNetworkAdapterExist(char *iGUID)
{
	int i;
	for (i = 0; i < TotalNetAdapters; i++)
	{
		if (!pNetAdapters[i].Set) continue;
			if (strcmp(pNetAdapters[i].GUIDA, iGUID) == 0) return 1;
	}
	return 0;
}

int FindNetworkAdapterByDevice(PDEVICE_OBJECT DeviceObject)
{
	int i;
	for (i = 0; i < TotalNetAdapters; i++)
	{
		if (pNetAdapters[i].DeviceObject == DeviceObject) return i;
	}
	return -1;
}

void InitalizeNetworkAdapters()
{
	if(pNetAdapters==NULL)
	pNetAdapters = (NetAdapters *)RtlAllocateMemoryV(sizeof(NetAdapters) * 60);
}

void FreeNetworkAdapters()
{
	if (pNetAdapters != NULL)
	RtlFreeMemoryV(pNetAdapters);
}

