# sentinel

minimal windows kernel driver and usermode controller proof-of-concept.

this project demonstrates basic communication between ring 3 (usermode) and ring 0 (kernel mode) using ioctls, as well as process creation monitoring

## structure

- **sentinel/**: the kernel driver source (`.sys`). handles irps and registers process notify routines.
- **sentinelusermode/**: the usermode console app (`.exe`). sends requests to the driver.

## features

- **ioctl communication**: creates a communication channel (`\\.\SentinelDriverLink`) to exchange string messages between user and kernel.
- **process monitoring**: uses `PsSetCreateProcessNotifyRoutine` to log when processes are created or exited (prints pid and parent pid to debug output).

## usage

1. **build**: compile the solution in visual studio (ensure you have the wdk installed).
2. **load driver**: enable test signing or use a mapper.
   ```cmd
   sc create Sentinel type= kernel binPath= "C:\path\to\Sentinel.sys"
   sc start Sentinel
