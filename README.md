# tmb-tools

TMB Bus userspace tools

## tmbdump

Implementation of a TMB Bus sniffer utility.

Options:
```
-a, --ascii                Print a ASCII dump of frame
-r, --raw                  Print a raw log entries
-x, --hex                  Print a hex dump of frame
-?, --help                 Give this help list
    --usage                Give a short usage message
```

## tmbexec

A test utility that allows you to perform all types of transactions

Usage:
```
tmbexec [OPTION...] IFACE
```
Options:
```
-a, --addr=<hex addr>      Bus addr
-b, --bg                   Background send mode
-c, --cyclic               Cyclic receive mode
-d, --dontwait             Immediate read local copy of an AP (Slave only)
-i, --ap=<idx>             AP index
-l, --size=<bytes>         Data size
-n, --nop                  Just keep open a AF_TMB socket
-p, --pattern=<hex byte>   Pattern char
-q, --quiet                Supress data dumps
-r, --recv                 Recv data
-s, --send                 Send data
-t, --period=<ms>          Data update period for the background mode
                           (default=1000)
-?, --help                 Give this help list
    --usage                Give a short usage message
```

## tmbtest

A test utility that can run data exchange in multiple threads.
Each thread transfers data through mmap'ed memory.
The main thread receives data. For example, __tmbtest 12 4__
means that 16 sockets are involved, 4 are transferred fro
master to slave and 12 from slave to master.

Usage:
```
tmbtest [OPTION...] <slave threads num> <master threads num>
```
Options:
```
-a, --addr=<hex value>     Slave device addr
-m, --master=<name>        Master net iface
-s, --slave=<name>         Slave net iface
-?, --help                 Give this help list
    --usage                Give a short usage message
```
