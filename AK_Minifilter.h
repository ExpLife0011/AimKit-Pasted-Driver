#include "AK_Main.h"
NTSTATUS NPUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS NPPostCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS MJCreatePreOpCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
NTSTATUS InitMiniFilter(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
NTSTATUS UnloadFilter();

extern int EAC_HWID_BYPASS;
extern int Redirect_DLL;