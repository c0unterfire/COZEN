Blackhat Arsernal COZEN

This is a POC tool on how one can protect data confidentiality by corrupting any data transfers to unauthorized usb drives.

The "Config" settings are stored in HKCU\Software\COZEN

[to add new drives to whitelist] set the "registerNewDrives" key to 1 - any new drives inserted will be added to the registry's "whitelist"

[to delete drives from whitelist] manually access the registry and delete the subkey from HKCU\Software\COZEN

Remember to disable "registerNewDrives" from the registry key by setting it back to 0 when done.
