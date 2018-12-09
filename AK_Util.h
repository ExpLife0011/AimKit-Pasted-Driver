#pragma once
#include "AK_Main.h"
void* RtlAllocateMemoryV(ULONG InSize);
void RtlFreeMemoryV(void* InPointer);
void RtlCopyMemoryV(PVOID InDest, PVOID InSource, ULONG InByteCount);
long RandRange(int min, int max);
int CompareByteArray(char *ByteArray1, PCHAR ByteArray2, PCHAR Mask, long Length);
DWORD64 FindSignature(void *BufferBytes, DWORD64 MemAddr, long ImageSize, PCHAR Signature, PCHAR Mask);
NTSTATUS AppendLogFile(char* fmt, ...);
void MyPrint(PSTR Format, ...);
void ToLower(unsigned char* Pstr);
void ToUpper(unsigned char* Pstr);
int InStr(char *str, char *tofind);
void RandString(char *str, size_t size);
BOOLEAN DestroyDriverInformation(PDRIVER_OBJECT pDriverObject, WCHAR* DriverName, ULONG64 DriverAddress, BOOLEAN bByName);