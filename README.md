# sentinel

a windows kernel driver for dynamic process blocking.

this project implements a ring 0 protection system that allows usermode applications to dynamically add process names to a kernel-level blacklist using ioctls.

## features

- **dynamic blacklisting**: add processes to the blocklist at runtime via `IOCTL_SENTINEL_ADD_BLACKLIST`.
- **process interception**: uses `PsSetCreateProcessNotifyRoutineEx` to monitor and block execution.
- **thread safety**: implements `FAST_MUTEX` and `LIST_ENTRY` to safely handle concurrent access between the notify routine and ioctl handlers.
- **memory management**: handles paged pool memory allocation using `ExAllocatePool2`.

## structure

- **sentinel/**: kernel driver (`.sys`). handles the blacklist logic, mutex locking, and process notification callbacks.
- **sentinelusermode/**: usermode app (`.exe`). interactive console for sending blacklist commands to the driver.

## usage

1. **build**
   - compile in visual studio (wdk required).
   - **critical**: ensure `/INTEGRITYCHECK` is set in linker -> command line for the driver, or the notify routine will fail to register.

2. **load**
   enable test signing or use a mapper, then register the service:

   ```cmd
   sc create Sentinel type= kernel binPath= "C:\path\to\Sentinel.sys"
   sc start Sentinel
   ```

3. **test**
   - run `SentinelController.exe` as administrator.
   - wait for the prompt: `[>] Enter a file path to add to the blacklist:`.
   - type a process name (e.g., `notepad.exe`) and press enter.
   - attempt to open that process. access will be denied.
   - view debug logs using **dbgview** (sysinternals) to see the blocking events.

## warning

this code runs in kernel mode. improper modification of the linked list or mutex logic will cause a system crash (bsod).
