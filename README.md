# Raw Traffic
This is a simple program to capture packets on an interface and save them to a file via the [libpcap](https://www.tcpdump.org/) network traffic capture library.

## Dependencies
This program requires the [libpcap](https://www.tcpdump.org/) development libraries. 

If you're on Debian, these libraries can be installed via the following command: 
```
sudo apt-get install libpcap-dev
```

## Compiling
If you're compiling with `gcc`, you must include the `-l pcap` argument.
```
gcc rawtraffic.c -o rawtraffic -l pcap
```

## Usage
```
./rawtraffic <interface> <port> [<savefile name>]
```

The interface and port number arguments are mandatory. You can optionally specify the name of the file to save the captured packets to. If you do not specify a filename as the third argument, then the default filename `capture` will be used.

You can set the desired number of packets to be captured by changing the value of this variable:
```
#define PCOUNT 0
```

If the value of `PCOUNT` is 0, the capture will continue indefinitely until an ending condition occurs. See `pcap_loop(3PCAP)` for details.

### Example
Capture packets on port `8000` on the loopback interface:
```
./rawtraffic lo 8000
```

Capture packets on port `25` on the enp4s0 interface, and save them to a file named `emails`:
```
./rawtraffic enp4s0 25 emails
```

Capture 20 packets:
```
#define PCOUNT 20
```
