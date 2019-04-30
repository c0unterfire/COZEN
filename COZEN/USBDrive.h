#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <dbt.h> 
#include <vector> 

#define REGISTRY_DISK_ENUM L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum" 
#define REGISTRY_COZEN L"SOFTWARE\\COZEN" 
#define DRIVE_PREFIX "\\\\.\\%c:"
#define RADIX 10
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define DRIVE_SIZE 26

#define DEVICE_COZEN 0x9000
#define IOCTL_COZEN_WRITEMEM  CTL_CODE(DEVICE_COZEN, 0x901, METHOD_BUFFERED, FILE_READ_ACCESS)

char FirstDriveFromMask(ULONG unitmask);
void MessagePump(HWND hWnd);
boolean checkAuthorization(WCHAR* driveIdentifier);
void registerUSBDrives(WCHAR* driveIdentifier);
boolean readRegistry(boolean getWhiteList);
void clearWhiteListVector();
void GetWhiteListDrives(HKEY hKey);
void lock_unlock_drives(boolean* drivesState);

extern boolean registrationMode;

boolean DoRegisterDeviceInterfaceToHwnd(
	IN GUID InterfaceClassGuid,
	IN HWND hWnd,
	OUT HDEVNOTIFY *hDeviceNotify
);
void deviceArrival(int wParam, PDEV_BROADCAST_DEVICEINTERFACE lParam);
INT_PTR WINAPI WinProcCallback(
	HWND hWnd,
	UINT message,
	WPARAM wParam,
	LPARAM lParam
);