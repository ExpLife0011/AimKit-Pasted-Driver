#pragma once
#include "AK_Main.h"
ULONG64 FindPspCreateProcessNotifyRoutine();
void EnumRemoveCreateProcessNotify();
void RestoreCreateProcessNotify();
void ClearCreateProcessNotify();