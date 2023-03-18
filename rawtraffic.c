#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
	pcap_t *handle;				   	// Session handle
	char *dev = argv[1];		   	// Device to capture on
	char errbuf[PCAP_ERRBUF_SIZE]; 	// Error string
	struct bpf_program fp;		   	// Compiled filter expression
	char filter_exp[] = "port 8000";// Filter expression
	bpf_u_int32 mask;			   	// Netmask of capturing device
	bpf_u_int32 net;			   	// IP of capturing device
	struct pcap_pkthdr header;		// Header pcap gives us
	const unsigned char *packet;	// The packet

	printf("Device: %s\n", dev);

	/**
	 * Open device and set filter
	*/

	// Find the IPv4 network number and netmask associated with device
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	// Open the device for capturing
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}

	// Compile the filter expression string
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}

	// Set the filter
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}

	/**
	 * Capture packet
	*/
	packet = pcap_next(handle, &header);

	printf("Packet length: %d\n", header.len);

	pcap_close(handle);

	return 0;
}