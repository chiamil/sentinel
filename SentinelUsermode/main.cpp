#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <string>

// custom ioctl codes matching the driver
#define IOCTL_SENTINEL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define IOCTL_SENTINEL_ADD_BLACKLIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main(int argc, char** argv) {
    HANDLE device;

    // open handle to the driver symbolic link
    device = CreateFileW(L"\\\\.\\SentinelDriverLink", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);

    if (device == INVALID_HANDLE_VALUE) {
        printf("Failed to open device. Error: %d\n", GetLastError());
        return 1;
    }

    // -----------------------------------------------------------
    // TEST IOCTL
    // -----------------------------------------------------------

    char userMessage[] = "Usermode says hello back! :)";
    char kernelMessage[256] = { 0 };
    DWORD bytesReturned;

    // send initial handshake message to kernel
    printf("[+] Issuing IOCTL_SENTINEL_TEST (0x%x). Sending message to kernel mode: %s\n", IOCTL_SENTINEL_TEST, userMessage);

    BOOL status = DeviceIoControl(device, IOCTL_SENTINEL_TEST, userMessage, sizeof(userMessage), kernelMessage, sizeof(kernelMessage), &bytesReturned, NULL);

    if (!status) {
        printf("[-] DeviceIoControl failed. Error: %d\n", GetLastError());
        CloseHandle(device);
        return 1;
    }

    printf("[+] IOCTL_SENTINEL_TEST (0x%x) completed.\n", IOCTL_SENTINEL_TEST);
    printf("[+] Received message from kernel mode: %s\n", kernelMessage);
    printf("[+] Bytes returned: %d\n", bytesReturned);

    // -----------------------------------------------------------
    // BLACKLIST IOCTL
    // -----------------------------------------------------------

    char kernelBuffer[256] = { 0 };
    DWORD bytesReturned2;

	// wchar_t blacklistEntry[] = L"notepad.exe"; 

    std::wstring userInput;
    
	// TODO: save this to a file or registry for persistence
    std::wcout << L"[?] Enter process name to blacklist (e.g., notepad.exe): ";
    std::getline(std::wcin, userInput);

    if (userInput.empty()) {
        std::wcout << L"[-] Input cannot be empty." << std::endl;
        return 1;
    }

	// calculate size of input in bytes (including null terminator)
	size_t inputSizeinBytes = (userInput.length() + 1) * sizeof(wchar_t);


    // send target process name to kernel blacklist
    printf("[>] Issuing IOCTL_SENTINEL_ADD_BLACKLIST (0x%x). Adding %ls to blacklist.\n.", IOCTL_SENTINEL_ADD_BLACKLIST, userInput.c_str());

    BOOL status2 = DeviceIoControl(device, IOCTL_SENTINEL_ADD_BLACKLIST, (LPVOID)userInput.c_str(), (DWORD)inputSizeinBytes, kernelBuffer, sizeof(kernelBuffer), &bytesReturned2, NULL);

    if (!status2) {
        printf("[-] DeviceIoControl failed. Error: %d\n", GetLastError());
        CloseHandle(device);
        return 1;
    }

    CloseHandle(device);
    return 0;
}