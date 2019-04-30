/*
	Code Referenced from:
		https://docs.microsoft.com/en-us/windows/desktop/DevIO/detecting-media-insertion-or-removal
		https://docs.microsoft.com/en-us/windows/desktop/devio/registering-for-device-notification
*/
#include "USBDrive.h"

// This GUID is for all USB serial host PnP drivers
GUID WceusbshGUID = { 0x25dbce51, 0x6c8f, 0x4a72,
					  0x8a,0x6d,0xb5,0x4c,0x2b,0x4f,0xc8,0x35 };

boolean drivesState[] = {1, 1, 1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 };

boolean registrationMode = false;
std::vector<WCHAR*> usbVector;

/*------------------------------------------------------------------
   FirstDriveFromMask( unitmask )

   Description
	 Finds the first valid drive letter from a mask of drive letters.
	 The mask must be in the format bit 0 = A, bit 1 = B, bit 2 = C,
	 and so on. A valid drive letter is defined when the
	 corresponding bit is set to 1.

   Returns the first drive letter that was found.
--------------------------------------------------------------------*/
char FirstDriveFromMask(ULONG unitmask)
{
	char i;

	for (i = 0; i < 26; ++i)
	{
		if (unitmask & 0x1)
			break;
		unitmask = unitmask >> 1;
	}

	return(i + 'A');
}

/*------------------------------------------------------------------
   DoRegisterDeviceInterfaceToHwnd( InterfaceClassGuid,
									hWnd,
									hDeviceNotify)

   Description
	 Registers the device or type of device for which a window will
	 receive notifications.

   Returns true if succeed else returns FALSE
--------------------------------------------------------------------*/
boolean DoRegisterDeviceInterfaceToHwnd(
	IN GUID InterfaceClassGuid,
	IN HWND hWnd,
	OUT HDEVNOTIFY *hDeviceNotify
)
{
	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;

	ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
	NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
	NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	NotificationFilter.dbcc_classguid = InterfaceClassGuid;

	*hDeviceNotify = RegisterDeviceNotification(
		hWnd,                       // events recipient
		&NotificationFilter,        // type of device
		DEVICE_NOTIFY_WINDOW_HANDLE // type of recipient handle
	);

	if (NULL == *hDeviceNotify)
	{
		return false;
	}

	return true;
}

/*------------------------------------------------------------------
   MessagePump( hWnd )

   Description
	 The message pump loops until the window is destroyed.

--------------------------------------------------------------------*/
void MessagePump(HWND hWnd)
{
	MSG msg;
	int retVal;

	while ((retVal = GetMessage(&msg, NULL, 0, 0)) != 0)
	{
		if (retVal == -1)
		{
			break;
		}
		else
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
}

/*------------------------------------------------------------------
   replaceSlash( input, output )

   Description
	 replace '/ 'with '_'

--------------------------------------------------------------------*/
void replaceSlash(WCHAR* input, WCHAR** output)
{
	if (output != NULL)
	{
		*output = (WCHAR*)calloc(wcslen(input) + 1, sizeof(WCHAR));
		if (*output != NULL)
		{
			for (size_t i = 0; i < wcslen(input); i++)
			{
				if (input[i] == '\\')
					(*output)[i] = '_';
				else
					(*output)[i] = input[i];
			}
		}
	}
}

/*------------------------------------------------------------------
   checkAuthorization( driveIdentifier )

   Description
	 check if attached USB drive is authorized

   Returns true if authorize
--------------------------------------------------------------------*/
boolean checkAuthorization(WCHAR* driveIdentifier)
{
	boolean ret = false;
	WCHAR* tmpDriveIdentifier;
	replaceSlash(driveIdentifier, &tmpDriveIdentifier);
	for (size_t i = 0; i < usbVector.size(); i++)
	{
		if (_wcsicmp(usbVector[i], tmpDriveIdentifier) == 0)
		{
			ret = true;
		}
	}
	free(tmpDriveIdentifier);
	return ret;
}

/*------------------------------------------------------------------
   registerUSBDrives( driveIdentifier )

   Description
	 register new USB Drives

--------------------------------------------------------------------*/
void registerUSBDrives(WCHAR* driveIdentifier)
{
	boolean found = false;
	WCHAR* tmpDriveIdentifier;
	replaceSlash(driveIdentifier, &tmpDriveIdentifier);

	// only register new drive if driveIdetifier is not in usbVector
	for (size_t i = 0; i < usbVector.size(); i++)
	{
		WCHAR* id = usbVector[i];
		//found
		if (_wcsicmp(id, tmpDriveIdentifier) == 0)
		{
			found = true;
			break;
		}
	}

	if (!found)
	{
		HKEY hKey;
		LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, REGISTRY_COZEN, 0, KEY_READ, &hKey);

		if (!result)
		{
			LONG err = RegCreateKeyEx(hKey, tmpDriveIdentifier, NULL, NULL,
				REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
			if (err == ERROR_SUCCESS)
				MessageBoxW(NULL, tmpDriveIdentifier, L"Registered", MB_OK);
		}
		RegCloseKey(hKey);
	}

	free(tmpDriveIdentifier);
}


/*------------------------------------------------------------------
   clearWhiteListVector( hKey )

   Description
	 free and clear usbVector

--------------------------------------------------------------------*/
void clearWhiteListVector()
{
	for (size_t i = 0; i < usbVector.size(); i++)
	{
		WCHAR* tmp = usbVector[i];
		free(tmp);
	}
	usbVector.clear();
}

/*------------------------------------------------------------------
   GetWhiteListDrives( hKey )

   Description
	 get all subkeys (Whitelisted drives) from hKey

--------------------------------------------------------------------*/
void GetWhiteListDrives(HKEY hKey)
{
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 

	DWORD i, retCode;

	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	clearWhiteListVector();

	// Enumerate the subkeys, until RegEnumKeyEx fails.
	if (cSubKeys)
	{
		for (i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				WCHAR* tmp = (WCHAR*)calloc(wcslen(achKey) + 1, sizeof(WCHAR));
				if (tmp != NULL)
				{
					memcpy(tmp, achKey, (wcslen(achKey) + 1) * sizeof(WCHAR));
					usbVector.push_back(tmp);
				}
			}
		}
	}
}

/*------------------------------------------------------------------
   readRegistry( getWhiteList )

   Description
	 return if RTZ is enabled or disabled
	 if getWhiteList is set to true, will update global usbVector

--------------------------------------------------------------------*/
boolean readRegistry(boolean getWhiteList)
{
	HKEY hKey;
	LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, REGISTRY_COZEN, 0, KEY_READ, &hKey);
	boolean registrationMode = false;

	if (result == ERROR_FILE_NOT_FOUND)
	{
		LONG err = RegCreateKeyEx(HKEY_CURRENT_USER, REGISTRY_COZEN, NULL, NULL,
			REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
		DWORD data = 1;
		err = RegSetValueEx(hKey, L"registerNewDrives", NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));
		registrationMode = true;
	}
	else
	{
		if (!result)
		{
			DWORD buffer = 0;
			DWORD buffersize = 10;
			if (!RegQueryValueExW(hKey, L"registerNewDrives", NULL, NULL, (BYTE*)&buffer, &buffersize))
			{
				if (buffer == 1) {

					registrationMode = true;
				}
				else
				{
					registrationMode = false;
				}
			}
			if (getWhiteList)
				GetWhiteListDrives(hKey);
		}
	}
	if (hKey != NULL)
		RegCloseKey(hKey);
	return registrationMode;
}

/*------------------------------------------------------------------
   lock_unlock_drives( drivesState )

   Description
	 send the drives state to the driver

--------------------------------------------------------------------*/
void lock_unlock_drives(boolean* drivesState) {
	HANDLE devh;
	DWORD bytesreturned;
	devh = CreateFileA("\\\\.\\Cozen",
		GENERIC_READ,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (devh == INVALID_HANDLE_VALUE) {
		printf("could not open device. GLE = %x\n", GetLastError());
		return;
	}

	DeviceIoControl(devh,
		(DWORD)IOCTL_COZEN_WRITEMEM,
		drivesState,
		DRIVE_SIZE,
		NULL,
		0,
		&bytesreturned,
		NULL);
	CloseHandle(devh);
}

/*------------------------------------------------------------------
   processDrive( driveLetter )

   Description
	 process drives and decide whether to block or allow

--------------------------------------------------------------------*/
void processDrive(char driveLetter)
{
	HANDLE drive;
	CHAR FileName[MAX_PATH];
	sprintf_s(FileName, MAX_PATH, DRIVE_PREFIX, driveLetter);
	drive = CreateFileA(FileName, 0, FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		NULL, CREATE_NEW | CREATE_ALWAYS, NULL, NULL);

	if ((drive != INVALID_HANDLE_VALUE))
	{
		VOLUME_DISK_EXTENTS diskExtents;
		DWORD dwSize;

		if (DeviceIoControl(
			drive,
			IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
			NULL,
			0,
			(LPVOID)&diskExtents,
			(DWORD) sizeof(diskExtents),
			(LPDWORD)&dwSize,
			NULL))
		{
			int diskNum = diskExtents.Extents->DiskNumber;
			HKEY hKey;
			int result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
				REGISTRY_DISK_ENUM, 0, KEY_READ, &hKey);
			if (!result)
			{
				WCHAR* data;
				WCHAR chrDiskNum[11];
				DWORD buffersize;

				data = (WCHAR*)calloc(MAX_PATH, sizeof(WCHAR));
				_itow_s(diskNum, chrDiskNum, 10, RADIX);
				if (!RegQueryValueExW(hKey, chrDiskNum, NULL, NULL, (BYTE*)data, &buffersize))
				{
					registrationMode = readRegistry(true); //refresh whitelist
					int driveIndex = driveLetter - 'A';
					if (!checkAuthorization((WCHAR*)data))
					{
						if (registrationMode == true)
						{
							registerUSBDrives(data);
							drivesState[driveIndex] = 1;
						}
						else {
							drivesState[driveIndex] = 0;
						}
					}
					else
					{
						drivesState[driveIndex] = 1;
					}
					lock_unlock_drives(drivesState);
				}
				free(data);
			}
			if (hKey != NULL)
				RegCloseKey(hKey);
		}
		CloseHandle(drive);
	}
}

/*------------------------------------------------------------------
   deviceArrival( wParam, lParam )

   Description
	 Process device arrival events

--------------------------------------------------------------------*/
void deviceArrival(int wParam, PDEV_BROADCAST_DEVICEINTERFACE lParam)
{
	PDEV_BROADCAST_DEVICEINTERFACE b = lParam;
	PDEV_BROADCAST_HDR lpdb = (PDEV_BROADCAST_HDR)lParam;

	switch (wParam)
	{
	case DBT_DEVICEARRIVAL:
		char driveLetter;
		if (lpdb->dbch_devicetype == DBT_DEVTYP_VOLUME)
		{
			PDEV_BROADCAST_VOLUME lpdbv = (PDEV_BROADCAST_VOLUME)b;

			driveLetter = FirstDriveFromMask(lpdbv->dbcv_unitmask);
			processDrive(driveLetter);
		}
		break;
	}
}

/*------------------------------------------------------------------
   WinProcCallback( hWnd, message, wParam, lParam )

   Description
	 WinProc Callback function. Device Arrival message pass through
	 here.

--------------------------------------------------------------------*/
INT_PTR WINAPI WinProcCallback(
	HWND hWnd,
	UINT message,
	WPARAM wParam,
	LPARAM lParam
)
{
	LRESULT lRet = 1;
	static HDEVNOTIFY hDeviceNotify;
	switch (message)
	{
	case WM_CREATE:
		if (!DoRegisterDeviceInterfaceToHwnd(
			WceusbshGUID,
			hWnd,
			&hDeviceNotify))
		{
			// Terminate on failure.
			ExitProcess(1);
		}

		break;

	case WM_DEVICECHANGE:
		deviceArrival(wParam, (PDEV_BROADCAST_DEVICEINTERFACE)lParam);
		break;

	case WM_CLOSE:
		UnregisterDeviceNotification(hDeviceNotify);
		DestroyWindow(hWnd);
		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;

	default:
		// Send all other messages on to the default windows handler.
		lRet = DefWindowProc(hWnd, message, wParam, lParam);
		break;
	}

	return lRet;
}