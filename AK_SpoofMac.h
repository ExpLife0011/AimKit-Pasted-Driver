#pragma once
#define OID_802_3_PERMANENT_ADDRESS       0x01010101
#define OID_802_3_CURRENT_ADDRESS         0x01010102
#define _NDIS_CONTROL_CODE(request, method) \
      CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, request, method, FILE_ANY_ACCESS)
#define IOCTL_NDIS_QUERY_GLOBAL_STATS \
_NDIS_CONTROL_CODE(0, METHOD_OUT_DIRECT)
#define NDIS_STATUS_SUCCESS				  ((int)STATUS_SUCCESS)

typedef struct NetAdapters {
	int Set;
	PDEVICE_OBJECT DeviceObject;
	PDRIVER_OBJECT NetworkDriver;
	PFILE_OBJECT FileObject;
	PDRIVER_DISPATCH RealNetworkDeviceControl;
	wchar_t GUID[128];
	char GUIDA[128];
	char NewMac[6];
	char DriverName[128];
} NetAdapters, *PNetAdapters;


typedef struct SpoofAdapterRequest {
	char GUIDA[128];
	wchar_t GUID[128];
	char NewMac[6];
} SpoofAdapterRequest, *PSpoofAdapterRequest;



NTSTATUS HookedNetworkDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void AddSpoofNetworkAdapter(SpoofAdapterRequest *req);
void RemUnSpoofAllAdapters();
int DoesNetworkAdapterExist(char *iGUID);
int FindNetworkAdapterByDevice(PDEVICE_OBJECT DeviceObject);
int FindNetworkDeviceByDriverName(char *idriver);
int DoesNetworkDriverExist(char *idriver);
void InitalizeNetworkAdapters();
void FreeNetworkAdapters();
void UniToAnsi(wchar_t *istr, char *ostr);