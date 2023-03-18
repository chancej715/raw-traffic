#include <stdio.h>
#include <pcap.h>

// User must pass device to capture as a command line argument.
int main(int argc, char *argv[])
{
	char *dev = argv[1], errbuf[PCAP_ERRBUF_SIZE];

	printf("Device: %s\n", dev);
	return (0);

	// Open the device for sniffing.
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return (2);
	}



	return 0;
}