#include <Windows.h>
#include <iostream>
#include <stdio.h>


// defining our custom IOCTL code
#define IOCTL_SENTINEL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) // microsoft recommends we can use any code past 0x800.
#define IOCTL_SENTINEL_ADD_BLACKLIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main(int argc, char** argv) {
	HANDLE device;
	device = CreateFileW(
		L"\\\\.\\SentinelDriverLink",
		GENERIC_ALL,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM,
		NULL
	);


	if (device == INVALID_HANDLE_VALUE) {
		printf("Failed to open device. Error: %d\n", GetLastError());
		return FALSE;
	}

	char userMessage[] = "Usermode says hello back! :)";
	char kernelMessage[256] = { 0 };
	DWORD bytesReturned;

	printf("[+] Issuing IOCTL_SENTINEL_TEST (0x%x). Sending message to kernel mode: %s\n.", IOCTL_SENTINEL_TEST, userMessage);
	BOOL status = DeviceIoControl(device, IOCTL_SENTINEL_TEST, userMessage, sizeof(userMessage), kernelMessage, sizeof(kernelMessage), &bytesReturned, NULL); // finally using DeviceIoControl to send our IOCTL to the driver
	printf("[+] IOCTL_SENTINEL_TEST (0x%x) completed.\n", IOCTL_SENTINEL_TEST);
	printf("[+] Received message from kernel mode: %s\n.", kernelMessage);
	printf("[+] Bytes returned: %d\n.", bytesReturned);
	if (!status) {
		printf("[-] DeviceIoControl failed. Error: %d\n", GetLastError());
		CloseHandle(device);
		return FALSE;
	}

	wchar_t blacklistEntry[] = L"notepad.exe";
	char kernelBuffer[256] = { 0 };
	DWORD bytesReturned2;
	printf("[>] Issuing IOCTL_SENTINEL_ADD_BLACKLIST (0x%x). Adding %ls to blacklist.\n.", IOCTL_SENTINEL_ADD_BLACKLIST, blacklistEntry);
	BOOL status2 = DeviceIoControl(device, IOCTL_SENTINEL_ADD_BLACKLIST, blacklistEntry, sizeof(blacklistEntry), kernelBuffer, sizeof(kernelBuffer), &bytesReturned2, NULL);
	if (!status2) {
		printf("[-] DeviceIoControl failed. Error: %d\n", GetLastError());
		CloseHandle(device);
		return FALSE;
	}
}