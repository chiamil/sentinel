#include <ntifs.h>

UNICODE_STRING dev, sym;

// defining our custom IOCTL code
#define IOCTL_SENTINEL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) // microsoft recommends we can use any code past 0x800.


VOID sCreateProceesNotifyRoutineEx(
    PEPROCESS				process,
    HANDLE					pid,
    PPS_CREATE_NOTIFY_INFO	createInfo
) {
    UNREFERENCED_PARAMETER(process);

    if (createInfo) {
        DbgPrint("[+] Process created (pid: %i): %wZ\n",
            pid,
            createInfo->CommandLine
        );

        if (wcsstr(createInfo->CommandLine->Buffer, L"notepad.exe")) {
            createInfo->CreationStatus = STATUS_ACCESS_DENIED;
        } 
        
    }
}

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

// defining our custom IOCTL code handler
NTSTATUS CustomIOCTLHandler(
    _In_ PDEVICE_OBJECT deviceObject, 
    _In_ PIRP           IRP
) {
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(IRP);
    char* kernelMessage = "1337 kernel hackerz"; // message we're sending back to usermode
    SIZE_T messageLength = strlen(kernelMessage) + 1;

	// handling our custom IOCTL code. we're calling it IOCTL_SENTINEL
    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SENTINEL) {
			DbgPrint("IOCTL_SENTINEL (0x%x) received.\n", stack->Parameters.DeviceIoControl.IoControlCode);
			DbgPrint("Input received from usermode: %s\n", (char*)IRP->AssociatedIrp.SystemBuffer);
            IRP->IoStatus.Status = STATUS_SUCCESS;
            IRP->IoStatus.Information = messageLength;
    }
    else {
        // if the IOCTL code is unknown, we return an error status
        DbgPrint("Unknown IOCTL (0x%x) received.\n", stack->Parameters.DeviceIoControl.IoControlCode);
        IRP->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IRP->IoStatus.Information = 0;
        IoCompleteRequest(IRP, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

	// copying our kernel message to the usermode buffer and sending it
	DbgPrint("Sending message to usermode: %s\n", kernelMessage);
    RtlCopyMemory(IRP->AssociatedIrp.SystemBuffer, kernelMessage, messageLength);
	IoCompleteRequest(IRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  driverObject,
    _In_ PUNICODE_STRING registryPath
) {
    UNREFERENCED_PARAMETER(registryPath);

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
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CustomIOCTLHandler;

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

