#include "AK_Main.h"
#include "Remap.h"
#include "Loader.h"

#include <ntstrsafe.h>

#pragma alloc_text(PAGE, BBDispatch)

/// <summary>
/// CTL dispatcher
/// </summary>
/// <param name="DeviceObject">Device object</param>
/// <param name="Irp">IRP</param>
/// <returns>Status code</returns>
NTSTATUS BBDispatch( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack;
    PVOID ioBuffer = NULL;
    ULONG inputBufferLength = 0;
    ULONG outputBufferLength = 0;
    ULONG ioControlCode = 0;
	PCHAR ok = "ok";
	PCHAR invalid = "invalid";

    UNREFERENCED_PARAMETER( DeviceObject );

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    irpStack = IoGetCurrentIrpStackLocation( Irp );
    ioBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (irpStack->MajorFunction)
    {
        case IRP_MJ_DEVICE_CONTROL:
        {
            ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

			DPRINT("AKDriver: FUCKING IO %lu", ioControlCode);

			if (ioControlCode == IOCTL_OB_AUTH)
			{
				DPRINT("AKDriver: FUCKING AUTH REQUEST");
				if (inputBufferLength > 0 && inputBufferLength < 256)
				{
					DPRINT("AKDriver: CORRECT FUCKING SIZE");
					//check if process asking is ok
					if (isRequestValid(ioBuffer, inputBufferLength))
					{
						DPRINT("AKDriver: Request valid\n");


						if (!FoundSigAuthProcess((int)PsGetCurrentProcessId_D()))
						{
							DPRINT("AKDriver:Auth sig not found for pid %d\n", (int)PsGetCurrentProcessId_D());
							Irp->IoStatus.Status = STATUS_SUCCESS;
							RtlZeroMemory(ioBuffer, inputBufferLength);
							RtlCopyMemory(ioBuffer, invalid, strlen(invalid));
							Irp->IoStatus.Information = strlen(invalid);
							irpStack->Parameters.DeviceIoControl.OutputBufferLength = strlen(invalid);
							status = Irp->IoStatus.Status;
							IoCompleteRequest(Irp, IO_NO_INCREMENT);
							return status;
						}
						else
						{
							DPRINT("AKDriver: Auth sig found for pid %d\n", (int)PsGetCurrentProcessId_D());
							Irp->IoStatus.Status = STATUS_SUCCESS;

							RtlZeroMemory(ioBuffer, inputBufferLength);
							RtlCopyMemory(ioBuffer, ok, strlen(ok));
							Irp->IoStatus.Information = strlen(ok);
							irpStack->Parameters.DeviceIoControl.OutputBufferLength = strlen(ok);
							status = Irp->IoStatus.Status;
							IoCompleteRequest(Irp, IO_NO_INCREMENT);
							return status;
						}

						/*
						Irp->IoStatus.Status = STATUS_SUCCESS;
						RtlZeroMemory(ioBuffer, inputBufferLength);
						RtlCopyMemory(ioBuffer, ok, strlen(ok));
						Irp->IoStatus.Information = strlen(ok);
						irpStack->Parameters.DeviceIoControl.OutputBufferLength = strlen(ok);
						status = Irp->IoStatus.Status;
						IoCompleteRequest(Irp, IO_NO_INCREMENT);
						return status;
						*/


					}
					else
					{
						DPRINT("AKDriver: Request not valid\n");
						Irp->IoStatus.Status = STATUS_SUCCESS;
						RtlZeroMemory(ioBuffer, inputBufferLength);
						RtlCopyMemory(ioBuffer, invalid, strlen(invalid));
						Irp->IoStatus.Information = strlen(invalid);
						irpStack->Parameters.DeviceIoControl.OutputBufferLength = strlen(invalid);
						status = Irp->IoStatus.Status;
						IoCompleteRequest(Irp, IO_NO_INCREMENT);
						return status;
					}

				}
				else
				{
					DPRINT("AKDriver: WRONG FUCKING SIZE");
					Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
					status = Irp->IoStatus.Status;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return status;
				}

			}

			//make sure the calling process id authorized before checking for other ioctl's

			if (!IsCallingPidAuthed())
			{
				int currentpid = (int)PsGetCurrentProcessId_D();
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				status = Irp->IoStatus.Status;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return status;
			}
			

            switch (ioControlCode)
            {
			case IOCTL_OB_Auth_Unload:
			{
				int callingpid = (int)PsGetCurrentProcessId_D();
				if (GHPid == callingpid)
				{
					DPRINT("AKDriver: Driver unload authorized.\n");
					GH_AuthDriverUnload = 1;
				}
			}
			break;

			case IOCTL_AK_MODULE_BASE:
			{
				MODBASE result = { 0 };
				Irp->IoStatus.Status = GetModuleBase((PMODBASE)ioBuffer, &result);
				RtlCopyMemory(ioBuffer, &result, sizeof(result));
				Irp->IoStatus.Information = sizeof(result);
			}
			break;

			case IOCTL_AK_DRIVER_NAME:
			{
				Irp->IoStatus.Status = STATUS_SUCCESS;
				RtlCopyMemory(ioBuffer, &DriverAnsiName, sizeof(DriverAnsiName));
				Irp->IoStatus.Information = sizeof(DriverAnsiName);
			}
			break;

			case IOCTL_AK_REMOVE_LOAD_IMAGE_NOTIFY:
			{
				AKDPRINT("AKDriver: removing LOAD_IMAGE_NOTIFY.\n");
				EnumRemoveLoadImageNotify();
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_RESTORE_LOAD_IMAGE_NOTIFY:
			{
				AKDPRINT("AKDriver: restoring LOAD_IMAGE_NOTIFY.\n");
				RestoreLoadImageNotify();
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_REMOVE_PROC_NOTIFY:
			{
				AKDPRINT("AKDriver: removing create_process_NOTIFY.\n");
				EnumRemoveCreateProcessNotify();
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_RESTORE_PROC_NOTIFY:
			{
				AKDPRINT("AKDriver: restoring proc_NOTIFY.\n");
				RestoreCreateProcessNotify();
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_REMOVE_THREAD_NOTIFY:
			{
				AKDPRINT("AKDriver: removing thread_NOTIFY.\n");
				EnumRemoveCreateThreadNotify();
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_RESTORE_THREAD_NOTIFY:
			{
				AKDPRINT("AKDriver: restoring thread_NOTIFY.\n");
				RestoreThreadNotify();
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_EAC_BYPASS_SET:
			{
				AKDPRINT("AKDriver: setting e bypass.\n");
				EAC_HWID_BYPASS = 1;
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_EAC_BYPASS_REMOVE:
			{
				AKDPRINT("AKDriver: removing e bypass.\n");
				EAC_HWID_BYPASS = 0;
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_START_OBS:
			{
				if(ObsRunning!=1)
				AKSetCallbacks();

				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_STOP_OBS:
			{
				if (ObsRunning == 1)
					FreeProcFilter();

				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_START_SPOOFER:
			{
				if (SpooferRunning != 1)
					HookDiskDriver();

				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_STOP_SPOOFER:
			{
				if (SpooferRunning == 1)
					UnhookDiskDriver();

				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

		
			case IOCTL_AK_ADD_PID_EXIT_MON:
			{
				/*
				RtlCopyMemory(&RUST_PID, ioBuffer, sizeof(RUST_PID));
				//RUST_PID = (int)ioBuffer;
				RUST_PID_RUNNING = 1;
				*/
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_CHECK_PID_EXIT_MON:
			{
				Irp->IoStatus.Status = STATUS_SUCCESS;
				RtlCopyMemory(ioBuffer, &RUST_PID_RUNNING, sizeof(int));
				Irp->IoStatus.Information = sizeof(int);
			}
			break;

			case IOCTL_AK_CHECK_PID_RUNNING:
			{
				Irp->IoStatus.Status = STATUS_SUCCESS;
				int temppid;

				RtlCopyMemory(&temppid, ioBuffer, sizeof(int));
				int running = CheckIfPIDRunning((HANDLE)temppid);
				RtlCopyMemory(ioBuffer, &running, sizeof(int));
				Irp->IoStatus.Information = sizeof(int);
			}
			break;

			case IOCTL_AK_TERMINATE_PID:
			{
				int tempppid;
				Irp->IoStatus.Status = STATUS_SUCCESS;
				RtlCopyMemory(&tempppid, ioBuffer, sizeof(int));
				AKTerminateProcess(tempppid);
			}
			break;



			case IOCTL_AK_SET_MEMCPY_PID:
			{
				/*
				if (inputBufferLength >= sizeof(int) && ioBuffer)
				{
					FastMemCpyPID = 0;
					if (PsLookupProcessByProcessId_D((HANDLE)ioBuffer, &pFastProcess) == STATUS_SUCCESS)
					{
						FastMemCpyPID = (int)ioBuffer;
					}
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
				else
				{
					Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
				}
				*/
			}
			break;

			case IOCTL_AK_ADD_OB_PID:
			{
				if (inputBufferLength >= sizeof(int) && ioBuffer)
				{
					OBAddPid((int)ioBuffer);
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
				else
				{
					Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
				}
			}
			break;

			case IOCTL_AK_REMOVE_OB_PID:
			{
				if (inputBufferLength >= sizeof(int) && ioBuffer)
				{
					OBRemovePid((int)ioBuffer);
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
				else
				{
					Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
				}
			}
			break;

			case IOCTL_AK_REMOVEALL_OB_PIDS:
			{
				ClearOBAuthPids();
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_GETMEM_PROTECT:
			{
				if (inputBufferLength >= sizeof(MEM_CHECK_PAGE_PROTECT) && ioBuffer)
				{
					MEMORY_BASIC_INFORMATION result = { 0 };
					GetMemPageInfo((PMEM_CHECK_PAGE_PROTECT)ioBuffer, &result);
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
				else
				{
					Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
				}
			}
			break;

			case IOCTL_AK_REDIRECT_DLL:
			{
				Redirect_DLL = 1;
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;

			case IOCTL_AK_STOP_REDIRECT_DLL:
			{
				Redirect_DLL = 0;
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;


			case IOCTL_OB_Driver_List:
			{
				Irp->IoStatus.Status = STATUS_SUCCESS;
				RtlZeroMemory(ioBuffer, inputBufferLength);

				int entries = GetDriversList((sKernDriverList*)ioBuffer);
				entries++;

				Irp->IoStatus.Information = sizeof(sKernDriverList) *entries;
				irpStack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(sKernDriverList) *entries;
			}
			break;

                case IOCTL_BLACKBONE_DISABLE_DEP:
                    {
                        if (inputBufferLength >= sizeof( DISABLE_DEP ) && ioBuffer)
                            Irp->IoStatus.Status = BBDisableDEP( (PDISABLE_DEP)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_SET_PROTECTION:
                    {
                        if (inputBufferLength >= sizeof( SET_PROC_PROTECTION ) && ioBuffer)
                            Irp->IoStatus.Status = BBSetProtection( (PSET_PROC_PROTECTION)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_GRANT_ACCESS:
                    {
                        if (inputBufferLength >= sizeof( HANDLE_GRANT_ACCESS ) && ioBuffer)
                            Irp->IoStatus.Status = BBGrantAccess( (PHANDLE_GRANT_ACCESS)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_COPY_MEMORY:
                    {
                        if (inputBufferLength >= sizeof( COPY_MEMORY ) && ioBuffer)
                            Irp->IoStatus.Status = BBCopyMemory( (PCOPY_MEMORY)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_ALLOCATE_FREE_MEMORY:
                    {
					//DPRINT("inputBufferLength %d sizeof( ALLOCATE_FREE_MEMORY ) %d  outputBufferLength %d sizeof( ALLOCATE_FREE_MEMORY_RESULT ) %d sizeof(booleen) %d \n", inputBufferLength, sizeof(ALLOCATE_FREE_MEMORY), outputBufferLength, sizeof(ALLOCATE_FREE_MEMORY_RESULT),sizeof(BOOLEAN));
                        if (inputBufferLength >= sizeof( ALLOCATE_FREE_MEMORY ) && outputBufferLength >= sizeof( ALLOCATE_FREE_MEMORY_RESULT ) && ioBuffer)
                        {
                            ALLOCATE_FREE_MEMORY_RESULT result = { 0 };
                            Irp->IoStatus.Status = BBAllocateFreeMemory( (PALLOCATE_FREE_MEMORY)ioBuffer, &result );

                            if (NT_SUCCESS( Irp->IoStatus.Status ))
                            {
                                RtlCopyMemory( ioBuffer, &result, sizeof( result ) );
                                Irp->IoStatus.Information = sizeof( result );
                            }
                        }
						else
						{
							DPRINT("BlackBone: wrong param size\n");
							Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
						}
                    }
                    break;

                case IOCTL_BLACKBONE_PROTECT_MEMORY:
                    {
                        if (inputBufferLength >= sizeof( PROTECT_MEMORY ) && ioBuffer)
                            Irp->IoStatus.Status = BBProtectMemory( (PPROTECT_MEMORY)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_MAP_MEMORY:
                    {
                        if (inputBufferLength >= sizeof( MAP_MEMORY ) && ioBuffer && outputBufferLength >= sizeof( ULONG ))
                        {
                            ULONG_PTR sizeRequired = 0;
                            PPROCESS_MAP_ENTRY pProcessEntry = NULL;

                            Irp->IoStatus.Status = BBMapMemory( (PMAP_MEMORY)ioBuffer, &pProcessEntry );

                            if (NT_SUCCESS( Irp->IoStatus.Status ) && pProcessEntry != NULL)
                            {
                                BBGetRequiredRemapOutputSize( &pProcessEntry->pageList, &sizeRequired );

                                // Return mapping results
                                if (outputBufferLength >= sizeRequired)
                                {
                                    PMAP_MEMORY_RESULT pResult = (PMAP_MEMORY_RESULT)ioBuffer;

                                    //
                                    // Fill output
                                    //
                                    pResult->count = 0;
                                    pResult->hostPage = (ULONGLONG)pProcessEntry->host.sharedPage;
                                    pResult->targetPage = (ULONGLONG)pProcessEntry->target.sharedPage;
                                    pResult->pipeHandle = (ULONGLONG)pProcessEntry->targetPipe;

                                    for (PLIST_ENTRY pListEntry = pProcessEntry->pageList.Flink;
                                          pListEntry != &pProcessEntry->pageList;
                                          pListEntry = pListEntry->Flink)
                                    {
                                        PMAP_ENTRY pEntry = CONTAINING_RECORD( pListEntry, MAP_ENTRY, link );

                                        pResult->entries[pResult->count].originalPtr = (ULONGLONG)pEntry->mem.BaseAddress;
                                        pResult->entries[pResult->count].newPtr = pEntry->newPtr;
                                        pResult->entries[pResult->count].size = (ULONG)pEntry->mem.RegionSize;
                                        pResult->count++;
                                    }

                                    Irp->IoStatus.Information = sizeRequired;
                                }
                                // Return number of bytes required 
                                else
                                {
                                    *(ULONG*)ioBuffer = (ULONG)sizeRequired;
                                    Irp->IoStatus.Information = sizeof( ULONG );
                                }
                            }
                        }
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_MAP_REGION:
                    {
                        if (inputBufferLength >= sizeof( MAP_MEMORY_REGION ) && 
                             outputBufferLength >= sizeof( MAP_MEMORY_REGION_RESULT ) && ioBuffer)
                        {
                            MAP_MEMORY_REGION_RESULT result = { 0 };
                            Irp->IoStatus.Status = BBMapMemoryRegion( (PMAP_MEMORY_REGION)ioBuffer, &result );

                            if (NT_SUCCESS( Irp->IoStatus.Status ))
                            {
                                RtlCopyMemory( ioBuffer, &result, sizeof( result ) );
                                Irp->IoStatus.Information = sizeof( result );
                            }
                        }
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_UNMAP_MEMORY:
                    {
                        if (inputBufferLength >= sizeof( UNMAP_MEMORY ) && ioBuffer)
                            Irp->IoStatus.Status = BBUnmapMemory( (PUNMAP_MEMORY)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_UNMAP_REGION:
                    {
                        if (inputBufferLength >= sizeof( UNMAP_MEMORY_REGION ) && ioBuffer)
                            Irp->IoStatus.Status = BBUnmapMemoryRegion( (PUNMAP_MEMORY_REGION)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_HIDE_VAD:
                    {
                        if (inputBufferLength >= sizeof( HIDE_VAD ) && ioBuffer)
                            Irp->IoStatus.Status = BBHideVAD( (PHIDE_VAD)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_INJECT_DLL:
                    {
                        if (inputBufferLength >= sizeof( INJECT_DLL ) && ioBuffer)
                            Irp->IoStatus.Status = BBInjectDll( (PINJECT_DLL)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_MAP_DRIVER:
                    {
                        if (inputBufferLength >= sizeof( MMAP_DRIVER ) && ioBuffer)
                        {
                            wchar_t buf[sizeof( ((PMMAP_DRIVER)ioBuffer)->FullPath )];
                            UNICODE_STRING ustrPath;

                            RtlCopyMemory( buf, ((PMMAP_DRIVER)ioBuffer)->FullPath, sizeof( ((PMMAP_DRIVER)ioBuffer)->FullPath ) );
                            RtlUnicodeStringInit( &ustrPath, buf );
                            Irp->IoStatus.Status = BBMMapDriver( &ustrPath );
                        }
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_UNLINK_HTABLE:
                    {
                        if (inputBufferLength >= sizeof( UNLINK_HTABLE ) && ioBuffer)
                            Irp->IoStatus.Status = BBUnlinkHandleTable( (PUNLINK_HTABLE)ioBuffer );
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;

                case IOCTL_BLACKBONE_ENUM_REGIONS:
                    {
                        if (inputBufferLength >= sizeof( ENUM_REGIONS ) && outputBufferLength >= sizeof( ENUM_REGIONS_RESULT ) && ioBuffer)
                        {
                            ULONG count = (outputBufferLength - sizeof( ULONGLONG )) / sizeof( MEMORY_BASIC_INFORMATION );
                            PENUM_REGIONS_RESULT pResult = ExAllocatePoolWithTag( PagedPool, outputBufferLength, BB_POOL_TAG );
                            pResult->count = count;

                            Irp->IoStatus.Status = BBEnumMemRegions( (PENUM_REGIONS)ioBuffer, pResult );

                            // Full info
                            if (NT_SUCCESS( Irp->IoStatus.Status ))
                            {
                                Irp->IoStatus.Information = sizeof( pResult->count ) + pResult->count * sizeof( MEMORY_BASIC_INFORMATION );
                                RtlCopyMemory( ioBuffer, pResult, Irp->IoStatus.Information );
                            }
                            // Size only
                            else
                            {
                                Irp->IoStatus.Status = STATUS_SUCCESS;
                                Irp->IoStatus.Information = sizeof( pResult->count );
                                RtlCopyMemory( ioBuffer, pResult, sizeof( pResult->count ) );
                            }

                            ExFreePoolWithTag( pResult, BB_POOL_TAG );
                        }
                        else
                            Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break; 
				case IOCTL_AK_SPOOF_MAC:
				{
					DbgPrint("Spoof mac 1");
					if (inputBufferLength >= sizeof(SpoofAdapterRequest) && ioBuffer)
					{
						DbgPrint("Spoof mac 2");
						AddSpoofNetworkAdapter((SpoofAdapterRequest *)ioBuffer);
						Irp->IoStatus.Status = STATUS_SUCCESS;
					}
					else
					{
						DbgPrint("Spoof mac 3");
						Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
					}
				}
				break;

				case IOCTL_AK_REMOVEALL_MAC_SPOOFS:
				{
					RemUnSpoofAllAdapters();
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
				break;

                default:
                    DPRINT( "BlackBone: %s: Unknown IRP_MJ_DEVICE_CONTROL 0x%X\n", __FUNCTION__, ioControlCode );
                    Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    break;
            }
        }
            break;
    }

    status = Irp->IoStatus.Status;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return status;
}