import pykd
from pykd import *
import re
from ctypes import *
from ctypes.wintypes import *
import os

kernel32 = windll.kernel32
ntdll = windll.ntdll

def alloc_unnamed_semaphore():
	hHandle = HANDLE(0)
	hHandle = kernel32.CreateSemaphoreA(None, 0, 3, None)
	if hHandle == None:
		print "[-] Error while creating Unnamed Semaphore"
		return 0
	print "Handle: " + hex(hHandle)
	return hex(hHandle)

def alloc_named_semaphore():
	hHandle = HANDLE(0)
	hHandle = kernel32.CreateSemaphoreA(None, 0, 3, "My little Semaphore")
	if hHandle == None:
		print "[-] Error while creating named Semaphore"
		return 0
	print "Handle: " + hex(hHandle)
	return hex(hHandle)

def alloc_unnamed_mutex():
	hHandle = HANDLE(0)
	hHandle = kernel32.CreateMutexA(None, False, None)
	if hHandle == None:
		print "[-] Error while creating Unnamed Mutex"
		return 0
	print "Handle: " + hex(hHandle)
	return hex(hHandle)

def alloc_named_mutex():
	hHandle = HANDLE(0)
	hHandle = kernel32.CreateMutexA(None, False, "Pool spraying is cool")
	if hHandle == None:
		print "[-] Error while creating named Mutex"
		return 0
	print "Handle: " + hex(hHandle)
	return hex(hHandle)

def alloc_icp():
	hHandle = HANDLE(0)
	hHandle = kernel32.CreateIoCompletionPort(-1, None, 0, 0)
	if hHandle == None:
		print "[-] Error while creating IoCompletionPort"
		return 0
	print "Handle: " + hex(hHandle)
	return hex(hHandle)

def alloc_named_job():
	hHandle = HANDLE(0)
	hHandle = kernel32.CreateJobObjectA(None, "Job")
	if hHandle == None:
		print "[-] Error while creating named Job"
		return 0
	print "Handle: " + hex(hHandle)
	return hex(hHandle)

def alloc_unnamed_job():
	hHandle = HANDLE(0)
	hHandle = kernel32.CreateJobObjectA(None, None)
	if hHandle == None:
		print "[-] Error while creating Unnamed Job"
		return 0
	print "Handle: " + hex(hHandle)
	return hex(hHandle)

def alloc_event():
	hHandle = HANDLE(0)
	hHandle = kernel32.CreateEventA(None, False, False, None)
	if hHandle == None:
		print "[-] Error while creating event"
		return 0
	print "Handle: " + hex(hHandle)
	return hex(hHandle)

def alloc_iocreserve():
	IO_COMPLETION_OBJECT = 1
	hHandle = HANDLE(0)
	ntdll.NtAllocateReserveObject(byref(hHandle), 0x0, IO_COMPLETION_OBJECT)
	hHandle = hHandle.value
	if hHandle == None:
		print "[-] Error while creating IoCompletionReserve"
		return 0
	print "Handle: " + hex(hHandle)
	return hex(hHandle)


def find_object_size(handle,name):
	#find windbg.exe process
	wp = dbgCommand('!process 0 0 windbg.exe')
	#print wp
	#extract process "address"
	process_tuples = re.findall( r'(PROCESS )([0-9a-f]*)(  SessionId)', wp)
	if process_tuples:
		process = process_tuples[0][1]
		print "Process: " + process

		#switch to process context
		dbgCommand(".process " + process)
	
		#find object "address"
		object_ref = dbgCommand("!handle " + hex(handle))
		object_tuples = re.findall( r'(Object: )([0-9a-f]*)(  GrantedAccess)', object_ref)
		if object_tuples:
			obj = object_tuples[0][1]
			print "Object: " + obj

			#find pool
			pools = dbgCommand("!pool " + obj)
			#print pools

			#find size
			size_re = re.findall(r'(\*[0-9a-f]{8} size:[ ]*)([0-9a-f]*)( previous)',pools)
			if size_re:
				print name + " objects's size in kernel: 0x" + size_re[0][1]
				if 'Named' in name:
					print "Dumping first 0x40 bytes of the pool chunk: "
					for i in range(0x40/4):
						print hex(ptrDWord(int(obj,16)-0x40+4*i))[2:].zfill(8)
					print dbgCommand("dd " + obj + "-40 L40/4")
				else:
					print "Dumping first 0x30 bytes of the pool chunk: "
					for i in range(0x30/4):
						print hex(ptrDWord(int(obj,16)-0x30+4*i))[2:].zfill(8)
					print dbgCommand("dd " + obj + "-30 L30/4")
				

	#close handle
	kernel32.CloseHandle(handle)

#attach to local kernel debugging
attachKernel()

#load symbols
dbgCommand('.symfix')
dbgCommand('.reload')

h = alloc_unnamed_mutex()
if h != 0: find_object_size(int(h,16),"Unnamed Mutex")

h = alloc_named_mutex()
if h != 0: find_object_size(int(h,16),"Named Mutex")

h = alloc_unnamed_job()
if h != 0: find_object_size(int(h,16),"Unnamed Job")

h = alloc_named_job()
if h != 0: find_object_size(int(h,16),"Named Job")

h = alloc_icp()
if h != 0: find_object_size(int(h,16),"IoCompletionPort")

h = alloc_event()
if h != 0: find_object_size(int(h,16),"Event")

h = alloc_iocreserve()
if h != 0: find_object_size(int(h,16),"IoCompletionReserve")

h = alloc_unnamed_semaphore()
if h != 0: find_object_size(int(h,16),"Unnamed Semaphore")

h = alloc_named_semaphore()
if h != 0: find_object_size(int(h,16),"Named Semaphore")

