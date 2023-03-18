# Raw Traffic
This is a simple program for capturing IPv4 network traffic on an interface and saving it to a binary file using libpcap.

## Dependencies
This program requires the libpcap development libraries. 

If you're on Debian, you can install these libraries via the following command: 
```
sudo apt-get install libpcap-dev
```

## Compiling
If you're compiling with `gcc`, you must include `-l pcap` to search the `libpcap` library when linking.
```
gcc rawtraffic.c -o rawtraffic -lpcap
```