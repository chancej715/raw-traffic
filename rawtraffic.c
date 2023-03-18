#include <stdio.h>
#include <stdlib.h>
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

	pcap_dumper_t *file_pointer;	// Pointer to the dump file
	char *filename = "packet";		// File to save to
	int pcount = 0;					// Number of packets read

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
		return 2;
	}

	// Set the filter
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}

	/**
	 * Capture and save packets
	*/
	// Open dump device for writing captured packet data
	file_pointer = pcap_dump_open(handle, filename);
	if (file_pointer == NULL)
	{
		fprintf(stderr, "Error opening file \"%s\" for writing: %s\n", filename, pcap_geterr(handle));
		return 2;
	}
	
	// Capture 1 packet and save to file
	pcount = pcap_dispatch(handle, 1, &pcap_dump, (char *)file_pointer);
	if (pcount < 0)
	{
		fprintf(stderr, "Error reading packets from interface %s", dev);
		return 2;
	}

	// Close file
	pcap_dump_close(file_pointer);

	// Close packet capture device
	pcap_close(handle);
































	// /**
	//  * Capture packet and write to file
	// */
	// packet = pcap_next(handle, &header);

	// // Write packet to file
	// file_pointer = pcap_dump_open(handle, filename);
	// if (file_pointer == NULL)
	// {
	// 	fprintf(stderr, "Couldn't open file \"%s\" for writing: %s\n", filename, pcap_geterr(handle));
	// 	return 2;
	// }

	// // Close the file
	// pcap_dump_close(file_pointer);

	// // Close the capture device
	// pcap_close(handle);

	return 0;
}