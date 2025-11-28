# sentinel

a minimal windows kernel driver and usermode controller proof-of-concept.

this project demonstrates basic communication between ring 3 (usermode) and ring 0 (kernel mode) using ioctls, as well as process creation monitoring with blocking capabilities.

## structure

- **sentinel/**: the kernel driver source (`.sys`). handles irps and registers extended process notify routines.
- **sentinelcontroller/**: the usermode console app (`.exe`). sends requests to the driver.

## features

- **ioctl communication**: creates a communication channel (`\\.\SentinelDriverLink`) to exchange string messages between user and kernel.
- **process blocking**: uses `PsSetCreateProcessNotifyRoutineEx` to intercept process creation.
  - currently configured to block **notepad.exe** from launching by setting `CreationStatus` to `STATUS_ACCESS_DENIED`.

## usage

1. **build**: compile the solution in visual studio (ensure you have the wdk installed).
   - **important**: go to project properties -> linker -> command line and add `/INTEGRITYCHECK` for the driver project, otherwise the extended notify routine will fail to register.
2. **load driver**: enable test signing or use a mapper.
   ```cmd
   sc create Sentinel type= kernel binPath= "C:\path\to\Sentinel.sys"
   sc start Sentinel
3. **test**:
   - run `SentinelController.exe` to test ioctl communication.
   - try opening `notepad.exe`. it should fail to launch.
   - open dbgview (sysinternals) to see the "process created" logs.
