# How to use the kex library
## Dependencies:
None, it only uses default Python system libraries, and this won’t change in the future, I want to keep it package independent. It works with Python 2.7.x, and wasn’t tested with 3.x.

## Sources
If I used a function I found somewhere, I tried to point this out in the comments. Specifically the GDI abuse ones are taken from: [GitHub - GradiusX/HEVD-Python-Solutions: Python solutions for the HackSysTeam Extreme Vulnerable Driver](https://github.com/GradiusX/HEVD-Python-Solutions). Although I modified them them in some cases, still the majority is unchanged, and as they build up big part of the code base, I wanted to highlight it here.

## Basic usage
### Functions to generate token stealing shell code:

These will get specific OS structure offsets, required for token stealing:
```
def getosvariablesx():
def getosvariablesx86():
def getosvariablesx64():
```

These will create token stealing shell code for the recognised platform.
```
def tokenstealingx86(RETVAL, extra = ""):
def tokenstealingx64(RETVAL, extra = ""):
def tokenstealing(RETVAL, extra = ""):
```

### Functions to use for pool spraying:

```
def allocate_object(object_to_use, variance):
def find_object_to_spray(required_hole_size):
def spray(required_hole_size):
def make_hole(required_hole_size, good_object):
def gimme_the_hole(required_hole_size):
def close_all_handles():
def calculate_previous_size(required_hole_size):
def pool_overwrite(required_hole_size,good_object):
```

See the CVE-2017-14153_windrvr1240-50_win7x86.py example for details. Basically if you know the hole size that will be overflown, these can mask the pool spraying process (no need to care about objects, allocation, overwrite data, etc…). Currently only works on Windows 7x86 SP1

### Functions to use for GDI object abuse:

These functions for working with the bitmaps, creation, read/write primitives.

```
def create_bitmap(width, height, cBitsPerPel):
def create_bitmaps(width, height, cBitsPerPel):
def set_address(manager_bitmap, address):
def write_memory(manager_bitmap, worker_bitmap, dst, src, len):
def read_memory(manager_bitmap, worker_bitmap, src, dst, len):
```

These to perform token stealing with the help of bitmaps:

```
def get_current_eprocess(manager_bitmap, worker_bitmap, pointer_EPROCESS):
def tokenstealing_with_bitmaps(manager_bitmap, worker_bitmap):
```

This set is leaking bitmap handle kernel pointers using GDISharedHandleTable, works up to Win10x64 v1511:

```
def get_gdisharedhandletable():
def get_pvscan0_address(bitmap_handle):
```

This set is leaking bitmap handle kernel pointers using AcceleratorTables, works up to Win10x64 v1607:

```
def get_accel_kernel_address(handle):
def alloc_free_accelerator_tables():
```

This set is leaking bitmap handle kernel pointers using windows, works up to Win10x64 v1703:

```
def findHMValidateHandle():
def PyWndProcedure(hWnd, Msg, wParam, lParam):
def allocate_free_window(classNumber, pHMValidateHandle):
def alloc_free_windows(classNugetosvariablesx86mber):
```

The following three groups the previous ones together and can be used as a single call:

```
def gdi_abuse_gdisharedhandletable_technique():
def gdi_abuse_accelerator_tables_technique():
def gdi_abuse_tagwnd_technique():
```

Lastly, this wraps the previous ones, and can give a WHAT / WHERE address for WWW vulnerabilities up to Win10x64 v1703:

```
def get_www_address_and_bitmaps():
```

The hacksys_arbitrary_overwrite-universal-win7-10x64.py can be check for how to use these.

### Others
There a few other functions as well. 

## Advanced usage

For now: Study the example codes and the function comments in the kex.py code. Almost all function has a description about what it does, and the input / output variables.


## 
#kernel