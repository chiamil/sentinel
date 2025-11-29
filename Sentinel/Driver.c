#include <ntifs.h>

UNICODE_STRING dev, sym;

// defining our custom IOCTL code
// microsoft recommends we can use any code past 0x800.
#define IOCTL_SENTINEL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define IOCTL_SENTINEL_ADD_BLACKLIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _BLACKLIST_ENTRY {
    LIST_ENTRY        listEntry;
    UNICODE_STRING    processName;
} BLACKLIST_ENTRY, * PBLACKLIST_ENTRY;

LIST_ENTRY BlacklistHead;
FAST_MUTEX BlacklistMutex;

// ---------------------------------------------------------------------------
// NOTIFY ROUTINE
// ---------------------------------------------------------------------------

VOID sCreateProceesNotifyRoutineEx(
    PEPROCESS                     process,
    HANDLE                        pid,
    PPS_CREATE_NOTIFY_INFO        createInfo
) {
    UNREFERENCED_PARAMETER(process);

    // we only care about process creation events. if createInfo is NULL, it means the process is being terminated
    if (!createInfo) {
        return;
    }

    PUNICODE_STRING processName = NULL;
    PLIST_ENTRY entry = BlacklistHead.Flink;

    SeLocateProcessImageName(process, &processName);

    if (NT_SUCCESS(SeLocateProcessImageName(process, &processName))) {
        ExAcquireFastMutex(&BlacklistMutex);

        // iterate through the blacklist and compare each entry with the name of the process being created
        while (entry != &BlacklistHead) {
            PBLACKLIST_ENTRY blacklistEntry = CONTAINING_RECORD(entry, BLACKLIST_ENTRY, listEntry);

            // using RtlSuffixUnicodeString instead of RtlEqualUnicodeString to allow blocking by suffix
            if (createInfo && RtlSuffixUnicodeString(&blacklistEntry->processName, processName, TRUE)) {
                createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                DbgPrint("[-] Blocked process creation (pid: %d): %wZ\n", (ULONG)(ULONG_PTR)pid, processName);
                break;
            }

            // move to the next entry in the list
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
        // adding a process name to the blacklist
        if (inputLength < sizeof(WCHAR) || inputLength > 512) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        // allocate memory for the doubly linked list entry
        PBLACKLIST_ENTRY nEntry = (PBLACKLIST_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(BLACKLIST_ENTRY), 'List');
        if (!nEntry) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // allocate memory for the buffer itself
        nEntry->processName.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, inputLength, 'Str');
        if (!nEntry->processName.Buffer) {
            ExFreePoolWithTag(nEntry, 'List');
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // setup unicode string headers
        nEntry->processName.Length = (USHORT)inputLength - sizeof(WCHAR);
        nEntry->processName.MaximumLength = (USHORT)inputLength;

        // copy the process name from usermode to kernelmode
        RtlCopyMemory(nEntry->processName.Buffer, IRP->AssociatedIrp.SystemBuffer, inputLength);

        // insert the new entry into the blacklist
        ExAcquireFastMutex(&BlacklistMutex);
        InsertTailList(&BlacklistHead, &nEntry->listEntry);
        ExReleaseFastMutex(&BlacklistMutex);

        DbgPrint("[+] Added to blacklist: %ws\n", nEntry->processName.Buffer);
        break;
    }

    case IOCTL_SENTINEL_TEST: {
        // simple test IOCTL that echoes a message from kernelmode to usermode
        char* kernelMessage = "1337 kernel hackerz";
        SIZE_T messageLength = strlen(kernelMessage) + 1;

        DbgPrint("IOCTL_SENTINEL_TEST (0x%x) received.\n", stack->Parameters.DeviceIoControl.IoControlCode);
        DbgPrint("Input received from usermode: %s\n", (char*)IRP->AssociatedIrp.SystemBuffer);

        if (stack->Parameters.DeviceIoControl.OutputBufferLength < messageLength) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // copy the message to usermode
        RtlCopyMemory(IRP->AssociatedIrp.SystemBuffer, kernelMessage, messageLength);
        info = messageLength;
        break;
    }

    default: {
        // handle unknown IOCTLs
        DbgPrint("Unknown IOCTL (0x%x) received.\n", stack->Parameters.DeviceIoControl.IoControlCode);
        IRP->IoStatus.Information = 0;
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    }

    // complete the IRP
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

    // register process notify routine
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