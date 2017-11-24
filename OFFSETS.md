# OFFSETS for kernel exploitation

## Window leak

|                    | Win7x86 SP1 | Win7x64 SP1 | Win8x64 | Win8.1x64 | Win10x64 v1511 | Win10x64 v1607 | Win10x64 v1703 | Win10x64 v1709 | 
|--------------------|-------------|-------------|---------|-----------|----------------|----------------|----------------|----------------| 
| Windows handle     | ?           | 0x0         | 0x0     | 0x0       | 0x0            | 0x0            | 0x0            | 0x0            | 
| pSelf              | ?           | 0x20        | 0x20    | 0x20      | 0x20           | 0x20           | 0x20           | 0x20           | 
| pcls               | ?           | 0x98        | 0x98    | 0x98      | 0x98           | 0x98           | 0xa8           | 0xa8           | 
| lpszMenuNameOffset | ?           | 0x88        | 0x88    | 0x88      | 0x88           | 0x88           | 0x90           | 0x98           | 

## BITMAP

|                    | Win7x86 SP1 | Win7x64 SP1 | Win8x64 | Win8.1x64 | Win10x64 v1511 | Win10x64 v1607 | Win10x64 v1703 | Win10x64 v1709 | 
|--------------------|-------------|-------------|---------|-----------|----------------|----------------|----------------|----------------| 
| BITMAP_min_size    | ?           | 0x350       | 0x360   | 0x370     | 0x370          | 0x370          | 0x370          | NA             | 
| BITMAP_data_offset | ?           | 0x238       | 0x250   | 0x258     | 0x258          | 0x260          | 0x260          | NA             | 

## PALETTE

|                    | Win7x86 SP1 | Win7x64 SP1 | Win8x64 | Win8.1x64 | Win10x64 v1511 | Win10x64 v1607 | Win10x64 v1703 | Win10x64 v1709 | 
|--------------------|-------------|-------------|---------|-----------|----------------|----------------|----------------|----------------| 
| pFirstColor_offset | 0x4c        | 0x80        | 0x80    | 0x80      | 0x80           | 0x78           | 0x78           | 0x78           | 
| apalColors_offset  | 0x54        | 0x90        | 0x90    | 0x90      | 0x90           | 0x88           | 0x88           | 0x88           | 

## Shellcodes x86

|                             | WinXPx86 SP3 | Win2003x86 SP2 | Vistax86 SP1 / SP2 | Win2008x86 SP2 | Win7x86 SP1 | 
|-----------------------------|--------------|----------------|--------------------|----------------|-------------| 
| KTHREAD_Process             | 0x44         | 0x38           | 0x48               | 0x48           | 0x50        | 
| EPROCESS_UniqueProcessId    | 0x84         | 0x94           | 0x9c               | 0x9c           | 0xb4        | 
| EPROCESS_ActiveProcessLinks | 0x88         | 0x98           | 0xa0               | 0xa0           | 0xb8        | 
| EPROCESS_Token              | 0xc8         | 0xd8           | 0xe0               | 0ce0           | 0xf8        | 
| EPROCESS_ImageFileName      | ?            | ?              | ?                  | ?              | ?           |
| TOKEN_IntegrityLevelIndex   | ?            | ?              | ?                  | ?              | ?           |

## Shellcodes x64

|                             | Win2003x64 | Win7x64 SP1 | Win8x64 | Win8.1x64 | Win10x64 v1511 | Win10x64 v1607 | Win10x64 v1703 | Win10x64 v1709 | 
|-----------------------------|------------|-------------|---------|-----------|----------------|----------------|----------------|----------------| 
| KTHREAD_Process             | 0x68       | 0x70        | 0xb8    | 0xb8      | 0xb8           | 0xb8           | 0xb8           | 0xb8           | 
| EPROCESS_UniqueProcessId    | 0xd8       | 0x180       | 0x2e0   | 0x2e0     | 0x2e8          | 0x2e8          | 0x2e0          | 0x2e0          | 
| EPROCESS_ActiveProcessLinks | 0xe0       | 0x188       | 0x2e8   | 0x2e8     | 0x2f0          | 0x2f0          | 0x2e8          | 0x2e8          | 
| EPROCESS_Token              | 0x160      | 0x208       | 0x348   | 0x348     | 0x358          | 0x358          | 0x358          | 0x358          | 
| EPROCESS_ImageFileName      | ?          | 0x2e0       | 0x438   | 0x438     | 0x450          | 0x450          | 0x450          | 0x450          | 
| TOKEN_IntegrityLevelIndex   | ?          | 0xc8        | 0xd0    | 0xd0      | 0xd0           | 0xd0           | 0xd0           | 0xd0           | 

## HalDispatchTable

|                            | WinXPx86 SP3 | Win2003x86 SP3 | Win7x86 SP1 | Win7x64 SP1 | Win8x64 | Win8.1x64 | Win10x64 v1511 | Win10x64 v1607 | Win10x64 v1703 | Win10x64 v1709 | 
|----------------------------|--------------|----------------|-------------|-------------|---------|-----------|----------------|----------------|----------------|----------------| 
| HaliQuerySystemInformation | 0x16bba      | 0x1fa1e        | 0x278a2     | 0x398e8     | ?       | ?         | ?              | ?              | ?              | ?              | 
| HalpSetSystemInformation   | 0x19436      | 0x21c60        | 0x281b4     | ?           | ?       | ?         | ?              | ?              | ?              | ?              | 

