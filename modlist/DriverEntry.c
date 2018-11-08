#include <ntifs.h>
#include <intrin.h>
#include <ntimage.h>
#include "DriverEntry.h"

// PsLoadedModuleList is an exported symbol, but if symbols weren't available
// a method of finding the PsLoadedModuleList follows:
//
// 1) Get KernelBase by backing up page by page from NtBuildNumber, making sure
//    it is a valid address. Check if it is the DOS_HEADER
// 2) Find .data section, this is where the PKDDEBUGGER_DATA64 structure will be.
//    This used to be found at KPCR->KdVersionBlock, which is now NULL
// 3) Search the .data section for the tag KDBG ('GBDK'). This is part of the structure
// 4) Get base address of structure and then we have acess to PsLoadedModuleList

#ifdef DBG
#define DBGPRINT(lvl, fmt, ...) DbgPrintEx(DPFLTR_DEFAULT_ID, lvl , fmt, __VA_ARGS__)
#else
#define DBGPRINT(fmt, ...)
#endif

// CodeMachine Virtual Address Layout
// https://www.codemachine.com/article_x64kvas.html
#define INITIAL_LOADER_MAPPING_BASE_MIN (PCHAR)0xFFFFF80000000000

// KPCR.KPRCB.IdleThread
#define IDLETHREAD_OFFSET 0x198

// PKDDEBUGGER_DATA64.Header.OwnerTag
#define KDBG_OWNERTAG 'GBDK'


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID DriverUnload( PDRIVER_OBJECT DriverObject);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT,DriverEntry)
#endif


#define MODULE_DUMP_DEVICE_NAME    L"\\Device\\GhostHook"

PIMAGE_DOS_HEADER GetKernelBase()
{
    PCHAR idleThread = (PCHAR)PAGE_ALIGN(__readgsqword(IDLETHREAD_OFFSET));
    for (PCHAR scandown = idleThread; scandown > INITIAL_LOADER_MAPPING_BASE_MIN; scandown -= PAGE_SIZE)
    {
        if (MmIsAddressValid(scandown))
        {
            if (((PIMAGE_DOS_HEADER)scandown)->e_magic == IMAGE_DOS_SIGNATURE)
            {
                return (PIMAGE_DOS_HEADER)scandown;
            }
        }
    }
    return NULL;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING usDeviceName;
    PDEVICE_OBJECT DeviceObject = NULL;
    PIMAGE_DOS_HEADER kernelbase = NULL;
    PKDDEBUGGER_DATA64 pDbgData = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);
    DBGPRINT(DPFLTR_TRACE_LEVEL, "%s DriverObject=%p\n", __FUNCTION__, DriverObject);

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
  
    // Create Device
    RtlInitUnicodeString(&usDeviceName, MODULE_DUMP_DEVICE_NAME);
    if(!NT_SUCCESS((Status = IoCreateDevice(
        DriverObject,
        0,
        &usDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DeviceObject))))
    {
        DBGPRINT(DPFLTR_ERROR_LEVEL, "%s IoCreateDevice Failed: 0x%08X\n", __FUNCTION__, Status);
        goto end;
    }
    
    // 1) Get Kernel Base
    if (NULL == (kernelbase = GetKernelBase()))
    {
        DBGPRINT(DPFLTR_ERROR_LEVEL, "%s Failed To find KernelBase\n", __FUNCTION__);
        goto end;
    }

    // 2) Get .data section
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PCHAR)kernelbase + (kernelbase->e_lfanew));
    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sh++)
    {
        if (memcmp(sh->Name, ".data", 5) == 0)
        {
            // 3) Search For KDBG Tag
            for (PULONG ul = (PULONG)((PCHAR)kernelbase + sh->VirtualAddress); 
                 ul < (PULONG)(((PCHAR)kernelbase + sh->VirtualAddress) + sh->Misc.VirtualSize);
                 ul++)
            {
                if (*ul == KDBG_OWNERTAG)
                {
                    // 4) Get Base Address of KDDEBUGGER_DATA64
                    pDbgData = (PKDDEBUGGER_DATA64)CONTAINING_RECORD(ul, DBGKD_DEBUG_DATA_HEADER64, OwnerTag);
                    break;
                }
            }
            break;
        }
    }
    if (NULL == pDbgData)
    {
        DBGPRINT(DPFLTR_ERROR_LEVEL, "%s Failed To find KDDEBUGGER_DATA\n", __FUNCTION__);
        goto end;
    }
    
    // Dump Module List
    PLDR_DATA_TABLE_ENTRY le = (PLDR_DATA_TABLE_ENTRY)(((PLDR_DATA_TABLE_ENTRY)(pDbgData->PsLoadedModuleList))->InLoadOrderLinks.Flink);
    do
    {
        DBGPRINT(DPFLTR_TRACE_LEVEL, "%s %p : %wZ\n", __FUNCTION__, le->DllBase, le->BaseDllName);
        le = (PLDR_DATA_TABLE_ENTRY)le->InLoadOrderLinks.Flink;
    } while (le != (PLDR_DATA_TABLE_ENTRY)pDbgData->PsLoadedModuleList);

    Status = STATUS_SUCCESS;
end:
    if (!NT_SUCCESS(Status))
    {
        if (DeviceObject) { IoDeleteDevice(DeviceObject); }
    }
    return Status;
} // DriverEntry()

VOID
DriverUnload(
    PDRIVER_OBJECT DriverObject)
{
    IoDeleteDevice(DriverObject->DeviceObject);
} // DriverUnload()


NTSTATUS
DispatchCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    DBGPRINT(DPFLTR_TRACE_LEVEL, "%s DeviceObject=%p Irp=%p\n", __FUNCTION__, DeviceObject, Irp);

    // Step #6 : Setup the appropriate values in IRP.IoStatus
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    // Step #7 : Complete the IRP (IoCompleteRequest())
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
} // DispatchCreateClose()