#pragma once
#include "AK_Main.h"
int FoundSigAuthProcess(int pid);
int isRequestValid(char *idata, int idatalen);
int IsCallingPidAuthed();
int IsUnloadAuthed();

extern int GH_AuthDriverUnload;