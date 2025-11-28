#include <ntifs.h>

UNICODE_STRING dev, sym;

VOID sCreateProcessNotifyRoutineEx(
    PEPROCESS process,
    HANDLE pid,
    PPS_CREATE_NOTIFY_INFO createInfo
) {
    HANDLE ppid = createInfo->ParentProcessId;
    if (createInfo != NULL) {
        if (wcsstr(createInfo->CommandLine->Buffer, L"Notepad") != NULL) {
            DbgPrint("Notepad process is being created!\n");
            createInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }

        PUNICODE_STRING processName = NULL, parentProcessName = NULL;

        PsLookupProcessByProcessId(ppid, &process);
        SeLocateProcessImageName(process, &parentProcessName);

        PsLookupProcessByProcessId(pid, &process);
        SeLocateProcessImageName(process, &processName);

        DbgPrint("Process Created: %wZ (PID: %p) Parent: %wZ (PPID: %p)\n",
            processName,
            pid,
            parentProcessName,
            ppid
        );
    }
    else {
        DbgPrint("Process Exited: PID: %p\n", pid);
    }
}



NTSTATUS DriverUnload(
    _In_ PDRIVER_OBJECT driverObject
) {
    IoDeleteDevice(driverObject->DeviceObject);
    PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, TRUE);
    DbgPrint("Driver unloaded. Goodbye, Driver World!\n");

    return STATUS_SUCCESS;
}

NTSTATUS MajorFunctions(PDEVICE_OBJECT deviceObject, PIRP IRP) {
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(IRP);
    switch (stackLocation->MajorFunction) {
    case IRP_MJ_CREATE:
        DbgPrint("Handle opened.");
        break;
    case IRP_MJ_CLOSE:
        DbgPrint("Handle closed.");
        break;
    
    default:
        break;
    }

    IRP->IoStatus.Status = STATUS_SUCCESS;
    IRP->IoStatus.Information = 0;
    IoCompleteRequest(IRP, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

NTSTATUS customIOCTLHandler(
    PDRIVER_OBJECT deviceObject, 
    PIRP IRP
) {
    UNREFERENCED_PARAMETER(deviceObject);
    PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(IRP);
    char* kernelMessage = "1337 kernel hackerz";
    
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  driverObject,
    _In_ PUNICODE_STRING registryPath
) {
    UNREFERENCED_PARAMETER(registryPath);

    RtlInitUnicodeString(&dev, L"\\Device\\SentinelDriver");
    RtlInitUnicodeString(&sym, L"\\??\\SentinelDriverLink");

    NTSTATUS status = 0;

    driverObject->DriverUnload = DriverUnload;

	IoCreateDevice(driverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &driverObject->DeviceObject);
    if (!NT_SUCCESS(status))
        DbgPrint("Couldn't create device %wZ.", dev);
    else
        DbgPrint("Device %wZ created.", dev);

    status = IoCreateSymbolicLink(&sym, &dev);
    if (!NT_SUCCESS(status))
        DbgPrint("Symbolic link %wZ created.", dev);
    else
        DbgPrint("Error creating Symbolic link %wZ.", dev);

    // handling IO requests from usermode
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = customIOCTLHandler;

    // routines that execute when a handle to my devices link is opened or closed.
    driverObject->MajorFunction[IRP_MJ_CREATE] = MajorFunctions;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = MajorFunctions;

    DbgPrint("Driver loaded. Hello, Driver World!\n");

	PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, FALSE);
    DbgPrint("Listening...");

    return STATUS_SUCCESS;
}

