// credits to Tim Carstens sniffer.c
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/*
 * main struct that is at the top
*/
struct Init {
		struct Domains *Dptr;
};

typedef struct Init Init;

struct Domains {
	u_int count;
	struct Domain *dptr[0];
};

typedef struct Domains Domains;

/*
 * struct to store data on domain
*/

struct Domain {
		u_int GET, POST;
		u_int num_requests;
		u_int total_requests;
		char name[32];
		struct Request *requests[0];
};

typedef struct Domain Domain;

/*
 * struct to store requests about a domain
*/
struct Request {
		u_int count;	
		char url[32];
};

typedef struct Request Request;

/*
 * allocates and creates a domain struct
*/
void AddDomain(Init *init, char *host)
{
	int count;
	count = init->Dptr->count;

	// first domain
	if (init->Dptr->count == 0) {

		Domain *domain = calloc(1, sizeof(struct Domain));
		init->Dptr->dptr[0] = domain;
		init->Dptr->count++;
		strncpy(init->Dptr->dptr[0]->name, host, 32);
		init->Dptr->dptr[0]->GET = 0;
		init->Dptr->dptr[0]->POST = 0;

		Request *request = calloc(1, sizeof(struct Request));
		init->Dptr->dptr[0]->requests[0] = request;
		init->Dptr->dptr[0]->requests[0]->count = 0;
		init->Dptr->dptr[0]->num_requests = 0;
		init->Dptr->dptr[0]->total_requests = 0;
	}
	else {
		Domain *domain = calloc(1, sizeof(struct Domain));
		init->Dptr->dptr[count] = domain;
		init->Dptr->count++;
		strncpy(init->Dptr->dptr[count]->name, host, 32);
		init->Dptr->dptr[count]->GET = 0;
		init->Dptr->dptr[count]->POST = 0;
	}

	return;
}

/*
 * add new request
*/
void AddRequest(Init *init, int *index, int *request_index, const char *req)
{
	if (init->Dptr->dptr[*index]->num_requests == 0) {
	Request *request = calloc(1, sizeof(struct Request));
	init->Dptr->dptr[*index]->requests[0] = request;
	init->Dptr->dptr[*index]->num_requests++;
	init->Dptr->dptr[*index]->total_requests++;
	init->Dptr->dptr[*index]->requests[0]->count = 0;
	init->Dptr->dptr[*index]->requests[0]->count++;
	strncpy(init->Dptr->dptr[*index]->requests[0]->url, req, 32);
	}
	else {
	Request *request = calloc(1, sizeof(struct Request));
	init->Dptr->dptr[*index]->requests[*request_index] = request;
	init->Dptr->dptr[*index]->num_requests++;
	init->Dptr->dptr[*index]->total_requests++;
	init->Dptr->dptr[*index]->requests[*request_index]->count = 0;
	init->Dptr->dptr[*index]->requests[*request_index]->count++;
	strncpy(init->Dptr->dptr[*index]->requests[*request_index]->url, req, 32);
	}
	
	return;
}

/*
 * increment an existing request
*/
void IncrementRequest(Init *init, int *index, int *request_index, const char *req)
{
	init->Dptr->dptr[*index]->total_requests++;
	init->Dptr->dptr[*index]->requests[*request_index]->count++;
	
	return;
}

void DomainRemove(Init *init, char *host)
{
	free(host);

	return;
}

/*
 * checks of domain exists
*/
int CheckifDomainExists(Init *init, char *host)
{
	int i;

	for (i = 0; i < init->Dptr->count; i++) {
		if (strncmp(init->Dptr->dptr[i]->name, host, strlen(host)) == 0)
			return 1;
		else
			return 0;
	}
}

/*
 * checks if request exists
*/
int CheckifRequestExists(Init *init, int *index, const char *request)
{
	int i;

	for (i = 0; i < init->Dptr->dptr[*index]->num_requests; i++) {
		if (strncmp(init->Dptr->dptr[*index]->requests[i]->url, request, strlen(request)) == 0)
			return i;
		else
			return -1;
	}
	return -1;

}

/*
 * gets index of domain 
*/
int GetDomainIndex(Init *init, char *host)
{
	int i;

	for (i = 0; i < init->Dptr->count; i++) {
		if (strncmp(init->Dptr->dptr[i]->name, host, strlen(host)) == 0)
			return i;
	}
}
	
/*
 * executes accounting
 * 
 * request: GET / HTTP/1.1
 * request: POST / HTTP/1.1
 * host: darkterminal.net
 * 
 */
void Tally(Init *init, int *http, const char *request, char *host)
{
	int index, request_index;
	
	if (!CheckifDomainExists(init, host))
		AddDomain(init, host);	

	index = GetDomainIndex(init, host);

	if (*http == 1) 		
		init->Dptr->dptr[index]->GET++;
	else if (*http == 2)
		init->Dptr->dptr[index]->POST++;

	if ((request_index = CheckifRequestExists(init, &index, request)) == -1) {

		// setting request_index to 0 so that AddRequest won't add a request using index -1
		if (request_index == -1)
			request_index = 0;
		
		AddRequest(init, &index, &request_index, request);	
	}
	else {
		IncrementRequest(init, &index, &request_index, request);
	}
	return;
}

	
Init *Initialize()
{
	Init *init = calloc(1, sizeof(Init));
	Domains *domains = calloc(1, sizeof(struct Domain));
	init->Dptr = domains;
	init->Dptr->count = 0;

	return init;
}

void TearDown(Init *init)
{
	free(init->Dptr);
	free(init);
	
	return;
}

/*
 * checks beginning of payload to see if it contains 'GET' or 'POST'
 * if it does then it returns 1 else it returns 0
 *
*/
int isGETPOST(const u_char *payload)
{
/*
	if (strncpy((char *)payload, "GET", 3) == 0)
		return 1;
	else if (strncpy((char *)payload, "POST", 4) == 0)
		return 2;
	else
		return 0;
*/

	// GET
	if ((payload[0] == '\x47') && (payload[1] == '\x45') && (payload[2] == '\x54'))
			return 1;
	// POST
	else if ((payload[0] == '\x50') && (payload[1] == '\x4f') && (payload[2] == '\x53') && (payload[3] == '\x54'))
			return 2;
	else
		return 0;

}

/*
 *  * dissect/print packet
 *   
*/
void
got_packet(Init *init, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 1;                   /* packet counter */
	int http;								/* HTTP method GET/POST */
	char *request;							/* the actual web request url */
	int num_request = 0, num_host = 0;		/* bytes to copy only request and host */
	char request_clean[32];					 
	char *host;								/* start of Host header */
	char host_clean[32];					/* start of Host header not including 'Host: ' */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    //printf("\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
	int num_packets = 10;           /* number of packets to capture */
    ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

/*
 *      *  OK, this packet is TCP.
 *           
*/
    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    // if TCP and ACK
   // if((ip->ip_p == IPPROTO_TCP) && ((tcp->th_flags) == 16))
	//	printf("HTTP packet\n");
/*
    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    printf("         ID: %d\n", (ip->ip_id));
    printf("        Seq: %lu\n", (tcp->th_seq));
    printf("        Ack: %lu\n", (tcp->th_ack));
    printf("        THF: %x\n", tcp->th_flags);
*/

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

/*
 *      * Print payload data; it might be binary, so don't just
 *           * treat it as a string.
 *                
*/
    //if ((size_payload > 0) && (http = isGETPOST(payload) != 0)){
    if ((size_payload > 0) && (http = isGETPOST(payload))){
        //printf("   Payload (%d bytes):\n", size_payload);
		//request = (strcspn(payload, "/")+1);
		//	printf("%.*s\n", (strcspn(payload, "/"), payload));

		// request
		num_request = strcspn(payload, "\r");
		//printf("%.*s\n", num_request, payload);
		strncpy(request_clean, payload, num_request);

		// host
		host = strstr(payload, "Host: ");
		num_host = strcspn(host, "\r");
		//printf("%.*s\n", num_host, host);
		strncpy(host_clean, host+6, num_host-6);
	
		// send results in
		Tally(init, &http, request_clean, host_clean);
	}

return;
}

int promiscuous(pcap_t *handle, char *dev, char *errbuf) {


	// open interface in promiscuous mode
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	// check if interface supports promiscuous mode
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}

	fprintf(stderr, "Initialized %s for promiscuous mode\n", dev);

	return 0;
}

int capture(pcap_t *handle, char *dev, char *errbuf, Init *init) {

	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	int num_packets = 25;           /* number of packets to capture */

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* now we can set our callback function */
	fprintf(stderr, "Capture starting\n");
	pcap_loop(handle, num_packets, (pcap_handler)got_packet, (u_char *)init);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return(0);
}

int main(int argc, char *argv[])  {

	int i, j, k;
	pcap_t *handle;

	Init *init;

	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	
	// grab default interface
	dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	fprintf(stderr, "Device: %s\n", dev);

	// Initialize data structures
	init = Initialize();

	//promiscuous(handle, dev, errbuf);
	capture(handle, dev, errbuf, init);

	// display results
	for (i = 0; i < init->Dptr->count; i++) {
		printf("Host: %s\t\tGET: %d\tPOST: %d\n", init->Dptr->dptr[i]->name, init->Dptr->dptr[i]->GET, init->Dptr->dptr[i]->POST);
		printf("Number of HTTP Requests: %d\t", init->Dptr->dptr[i]->total_requests);
		for (j = 0; j < init->Dptr->dptr[i]->num_requests; j++)
			printf("%s\tcount: %d\n", init->Dptr->dptr[i]->requests[j]->url, init->Dptr->dptr[i]->requests[j]->count);
	}


	// free up data structures
	TearDown(init);

	return(0);
}
