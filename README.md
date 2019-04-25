Blackhat Arsernal COZEN

USB-based devices are a common tool of choice for covert data exfiltration especially since large quantities of data can be stored on a small device. To prevent this, defences such as disabling USB ports or disabling the capacity to copy data to the USB device. While useful, this also has the effect of driving the attacker to resort to other means of data exfiltration (including stealing the laptop/ computer outright!). To this end, we believe that instead of completely denying the attacker this mode of attack, it may be useful to lead the attacker down a false path instead.

Cozen is a tool that seeks to foil USB-based data exfiltration by surreptitiously corrupting data as it is transferred to the USB-device – files and directories will appear as per normal, but the contents within will have been overwritten with garbage data. We hypothesize that a good percentage of data exfiltration attempts take place under some form of time pressure, and the attacker often has little time to double-check the integrity of the files that have been transferred to their USB device. In this regard, Cozen will be able to help prevent data exfiltration, or at the minimum, delay or disrupt the exfiltration process and reduce the attacker’s chance of success.

This is a POC tool on how one can protect data confidentiality by corrupting any data transfers to unauthorized usb drives.

The "Config" settings are stored in HKCU\Software\COZEN

[to add new drives to whitelist] set the "registerNewDrives" key to 1 - any new drives inserted will be added to the registry's "whitelist"

[to delete drives from whitelist] manually access the registry and delete the subkey from HKCU\Software\COZEN

Remember to disable "registerNewDrives" from the registry key by setting it back to 0 when done.
