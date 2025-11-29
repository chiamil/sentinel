#include <ntifs.h>

UNICODE_STRING dev, sym;

// defining our custom IOCTL code
#define IOCTL_SENTINEL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) // microsoft recommends we can use any code past 0x800.
#define IOCTL_SENTINEL_ADD_BLACKLIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _BLACKLIST_ENTRY {
    LIST_ENTRY		listEntry;
    UNICODE_STRING	processName;
} BLACKLIST_ENTRY, *PBLACKLIST_ENTRY;

LIST_ENTRY BlacklistHead;
FAST_MUTEX BlacklistMutex;

// ---------------------------------------------------------------------------
// NOTIFY ROUTINE
// ---------------------------------------------------------------------------

VOID sCreateProceesNotifyRoutineEx(
    PEPROCESS				process,
    HANDLE					pid,
    PPS_CREATE_NOTIFY_INFO	createInfo
) {
    UNREFERENCED_PARAMETER(process);

    if (!createInfo) {
        return;
    }

	PUNICODE_STRING processName = NULL;

    PLIST_ENTRY entry = BlacklistHead.Flink;

    SeLocateProcessImageName(process, &processName);

    if (NT_SUCCESS(SeLocateProcessImageName(process, &processName))) {
        ExAcquireFastMutex(&BlacklistMutex);

        while (entry != &BlacklistHead) {
            PBLACKLIST_ENTRY blacklistEntry = CONTAINING_RECORD(entry, BLACKLIST_ENTRY, listEntry);
            if (createInfo && RtlSuffixUnicodeString(&blacklistEntry->processName, processName, TRUE)) {
                createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                DbgPrint("[-] Blocked process creation (pid: %d): %wZ\n",
                    (ULONG)(ULONG_PTR)pid,
                    processName
                );
                break;
            }
            entry = entry->Flink;

        }
    }
    ExReleaseFastMutex(&BlacklistMutex);
    ExFreePool(processName);
}

// ---------------------------------------------------------------------------
// DISPATCH ROUTINES
// ---------------------------------------------------------------------------

NTSTATUS DriverUnload(
    _In_ PDRIVER_OBJECT driverObject
) {
    IoDeleteDevice(driverObject->DeviceObject);
	PsSetCreateProcessNotifyRoutineEx(sCreateProceesNotifyRoutineEx, TRUE);
    DbgPrint("Driver unloaded. Goodbye, Driver World!\n");

    return STATUS_SUCCESS;
}

NTSTATUS SentinelCreate(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP           IRP
) {
    UNREFERENCED_PARAMETER(deviceObject);
    DbgPrint("Handle opened.\n");

    IRP->IoStatus.Status = STATUS_SUCCESS;
    IRP->IoStatus.Information = 0;
    IoCompleteRequest(IRP, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS SentinelClose(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP           IRP
) {
    UNREFERENCED_PARAMETER(deviceObject);
    DbgPrint("Handle closed.\n");

    IRP->IoStatus.Status = STATUS_SUCCESS;
    IRP->IoStatus.Information = 0;
    IoCompleteRequest(IRP, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS SentinelDeviceControl(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP           IRP
) {
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(IRP);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    switch (controlCode) {

    case IOCTL_SENTINEL_ADD_BLACKLIST: {
        if (inputLength < sizeof(WCHAR) || inputLength > 512) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }
        PBLACKLIST_ENTRY nEntry = (PBLACKLIST_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(BLACKLIST_ENTRY), 'List');
        if (!nEntry) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        nEntry->processName.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, inputLength, 'Str');
        if (!nEntry->processName.Buffer) {
            ExFreePoolWithTag(nEntry, 'List');
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        nEntry->processName.Length = (USHORT)inputLength - sizeof(WCHAR); // length in bytes, excluding null terminator
        nEntry->processName.MaximumLength = (USHORT)inputLength; // total size of the buffer in b

        RtlCopyMemory(nEntry->processName.Buffer, IRP->AssociatedIrp.SystemBuffer, inputLength);

        ExAcquireFastMutex(&BlacklistMutex);
        InsertTailList(&BlacklistHead, &nEntry->listEntry);
        ExReleaseFastMutex(&BlacklistMutex);

        DbgPrint("[+] Added to blacklist: %ws\n", nEntry->processName.Buffer);
        break;
    }
    case IOCTL_SENTINEL_TEST: {
        char* kernelMessage = "1337 kernel hackerz";
        SIZE_T messageLength = strlen(kernelMessage) + 1;

        DbgPrint("IOCTL_SENTINEL_TEST (0x%x) received.\n", stack->Parameters.DeviceIoControl.IoControlCode);
        DbgPrint("Input received from usermode: %s\n", (char*)IRP->AssociatedIrp.SystemBuffer);
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < messageLength) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(IRP->AssociatedIrp.SystemBuffer, kernelMessage, messageLength);
        info = messageLength;
        break;

    }

    default: {
        DbgPrint("Unknown IOCTL (0x%x) received.\n", stack->Parameters.DeviceIoControl.IoControlCode);
        IRP->IoStatus.Information = 0;
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    }
    IRP->IoStatus.Status = status;
    IRP->IoStatus.Information = info;
    IoCompleteRequest(IRP, IO_NO_INCREMENT);
    return status;
}

// ---------------------------------------------------------------------
// DRIVER ENTRY
// ---------------------------------------------------------------------

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  driverObject,
    _In_ PUNICODE_STRING registryPath
) {
    UNREFERENCED_PARAMETER(registryPath);

    // Initialize the blacklist mutex and list head
    ExInitializeFastMutex(&BlacklistMutex);
    InitializeListHead(&BlacklistHead);

    DbgPrint("Driver loaded. Hello, Driver World!\n");

    // initializing device and symbolic link names
    RtlInitUnicodeString(&dev, L"\\Device\\SentinelDriver");
    RtlInitUnicodeString(&sym, L"\\??\\SentinelDriverLink");
    
	// creating device object & symbolic link
	IoCreateDevice(driverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &driverObject->DeviceObject);
    IoCreateSymbolicLink(&sym, &dev);

	// routine that executes when the driver is unloaded.
    driverObject->DriverUnload = DriverUnload;

	// handling IO requests from usermode using our custom IOCTL handler.
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SentinelDeviceControl;

    // routines that execute when a handle to our devices link is opened or closed.
    driverObject->MajorFunction[IRP_MJ_CREATE] = SentinelCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = SentinelClose;


    NTSTATUS result = PsSetCreateProcessNotifyRoutineEx(sCreateProceesNotifyRoutineEx, FALSE);
    if (result == STATUS_SUCCESS) {
        DbgPrint("Process notify routine set successfully.\n");
    }
    else {
		DbgPrint("Failed to set process notify routine. Status: 0x%x\n", result);
    }

    DbgPrint("Listening...\n");

    return STATUS_SUCCESS;
}

