# spoofs
imple Linux command line tool for sending TCP packets with arbitrary spoofed IP

compile:
gcc spoofs.c -o spoofs

use:

```
./spoofs -s 1.2.3.4 -d 192.168.0.8 -p 2-3

Ok. I've sent 2 packets to host 192.168.0.8 as host 1.2.3.4
```
