#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

#define SAVEFILE "capture" 		// Save filename
#define PCOUNT 15			// Number of packets to capture

void usage(char *progname)
{
	printf("Usage: %s <interface> <port> [<savefile name>]\n", basename(progname));
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			// Session handle
	char *dev = argv[1];		// Device to capture on
	char errbuf[PCAP_ERRBUF_SIZE];	// Error string
	char *port = argv[2];		// Port to monitor
	char filter_exp[] = "port ";   	// Filter expression
	struct bpf_program fp;		// Compiled filter expression
	bpf_u_int32 mask;		// Netmask of capturing device
	bpf_u_int32 net;		// IP of capturing device
	pcap_dumper_t *file_pointer;   	// Pointer to the dump file
	char filename[80];		// Name of file to save to
	int packet = 0;			// Number of packets captured

	// Device and port number arguments are required
	if (argc < 2)
	{
		usage(argv[0]);
		return 2;
	}

	/**
	 * Open device for capture and set capture filter
	 */

	// Open the device for capturing
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}

	// Find the IPv4 network number and netmask associated with device
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		return 2;
	}

	// Compile the filter expression string
	strncat(filter_exp, port, 65535);
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

	// Set filename
	if (argc >= 4)
		strncpy(filename, argv[3], sizeof(filename));
	else
		strcpy(filename, SAVEFILE);

	// Open dump device for writing captured packets
	file_pointer = pcap_dump_open(handle, filename);

	if (file_pointer == NULL)
	{
		fprintf(stderr, "Error opening file \"%s\" for writing: %s\n", filename, pcap_geterr(handle));
		return 2;
	}

	// Capture packets and save to file
	packet = pcap_loop(handle, PCOUNT, &pcap_dump, (char *)file_pointer);
	if (packet < 0)
	{
		fprintf(stderr, "Error reading packets from interface %s", dev);
		return 2;
	}

	// Close file
	pcap_dump_close(file_pointer);

	// Close packet capture device
	pcap_close(handle);

	return 0;
}
