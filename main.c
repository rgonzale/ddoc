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
#include <ncurses.h>
#include <signal.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Maximum number of Domains */
#define DOMAINS 1024

/* Maximum number of Requests per Domain */
#define REQUESTS 1024

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
 * main struct that is at the top of all the data structures
*/
struct Domains {
	u_int count;
	struct Domain *dptr[DOMAINS];
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
		struct Request *requests[REQUESTS];
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
void AddDomain(Domains *Dptr, char *host)
{
	int count;
	count = Dptr->count;

	Domain *domain = calloc(1, sizeof(struct Domain));
	
	Dptr->dptr[count] = domain;
	Dptr->count++;
	strncpy(Dptr->dptr[count]->name, host, 32);
	Dptr->dptr[count]->GET = 0;
	Dptr->dptr[count]->POST = 0;
	Dptr->dptr[count]->num_requests = 0;
	Dptr->dptr[count]->total_requests = 0;

	return;
}

/*
 * add new request
*/
void AddRequest(Domains *Dptr, int *index, int *request_index, char *req)
{
	Request *request = calloc(1, sizeof(struct Request));

	Dptr->dptr[*index]->requests[*request_index] = request;
	Dptr->dptr[*index]->num_requests++;
	Dptr->dptr[*index]->total_requests++;
	Dptr->dptr[*index]->requests[*request_index]->count = 0;
	Dptr->dptr[*index]->requests[*request_index]->count++;
	strncpy(Dptr->dptr[*index]->requests[*request_index]->url, req, 32);
	
	return;
}

/*
 * increment an existing request
*/
void IncrementRequest(Domains *Dptr, int *index, int *request_index, const char *req)
{
	Dptr->dptr[*index]->total_requests++;
	Dptr->dptr[*index]->requests[*request_index]->count++;
	
	return;
}

/*
 * checks of domain exists
*/
int CheckifDomainExists(Domains *Dptr, char *host)
{
	int i;

	for (i = 0; i < Dptr->count; i++) {
		if (strncmp(Dptr->dptr[i]->name, host, strlen(host)) == 0)
			return 1;
	}
	return 0;
}

/*
 * checks if request exists
*/
int CheckifRequestExists(Domains *Dptr, int *index, const char *request)
{
	int i;

	for (i = 0; i < Dptr->dptr[*index]->num_requests; i++) {
		if (strncmp(Dptr->dptr[*index]->requests[i]->url, request, strlen(request)) == 0)
			return i;
	}
	return -1;

}

/*
 * gets index of domain 
*/
int GetDomainIndex(Domains *Dptr, char *host)
{
	int i;

	for (i = 0; i < Dptr->count; i++) {
		if (strncmp(Dptr->dptr[i]->name, host, strlen(host)) == 0)
			return i;
	}
	// didn't find domain
	return -1;
}

/*
 * sorting function
 */
void sortDomains(Domains *Dptr, int *index)
{
	int i;
	struct Domain *tmp;
		for (i = *index; i > 0; i--) {
			if (Dptr->dptr[i]->total_requests > Dptr->dptr[i-1]->total_requests) {
				tmp = Dptr->dptr[i];
				Dptr->dptr[i] = Dptr->dptr[i-1];
				Dptr->dptr[i-1] = tmp;	
			}
	}
}

/*
 * main Ncurses update
 */
void NcursesUpdate(Domains *Dptr)
{
	int i;

	move(0,0);
	addstr("Total Requests\tGET\t\tPOST\t\tDomain\n");
	for (i = 0; i < Dptr->count; i++)
	//for (i = Dptr->count - 1; i > -1; i--)
		printw("%d\t\t%d\t\t%d\t\t%s\n", 	Dptr->dptr[i]->total_requests, 
											Dptr->dptr[i]->GET, 
											Dptr->dptr[i]->POST, 
											Dptr->dptr[i]->name);

	refresh();

}

	
/*
 * executes accounting
 * 
 * request: GET / HTTP/1.1
 * request: POST / HTTP/1.1
 * host: darkterminal.net
 * 
 */
void Tally(Domains *Dptr, int *http, char *request, char *host)
{
	int index, request_index;
	
	if (!CheckifDomainExists(Dptr, host))
		AddDomain(Dptr, host);	

	index = GetDomainIndex(Dptr, host);

	if (*http == 1) 		
		Dptr->dptr[index]->GET++;
	else if (*http == 2)
		Dptr->dptr[index]->POST++;

	request_index = CheckifRequestExists(Dptr, &index, request);

	// if request not found set to -1 and set to num_requests when adding a new one
	if (request_index == -1) {
		request_index = Dptr->dptr[index]->num_requests;
		
		AddRequest(Dptr, &index, &request_index, request);	
	}
	else {
		IncrementRequest(Dptr, &index, &request_index, request);
	}

	// sort the domains
	if (Dptr->count > 1 && index != 0)
		sortDomains(Dptr, &index);

	// call main update ncurses function
	NcursesUpdate(Dptr);
	return;
}
	
Domains *Initialize()
{
	Domains *Dptr = calloc(1, sizeof(Domains));
	Domains *domains = calloc(1, sizeof(struct Domain));
	Dptr = domains;
	Dptr->count = 0;

	return Dptr;
}

void TearDown(Domains *Dptr)
{
	int i, j, domains = 0;

	domains = Dptr->count;
	
	for (i = 0; i < domains; i++)
		for (j = 0; j < Dptr->dptr[i]->num_requests; j++)
			free(Dptr->dptr[i]->requests[j]);

	for (i = 0; i < domains; i++)
		free(Dptr->dptr[i]);

/*
	free(Dptr->dptr[0]->requests[0]);
	free(Dptr->dptr[1]->requests[0]);
	
	free(Dptr->dptr[0]);
	free(Dptr->dptr[1]);
*/

	free(Dptr);
	
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

/* ssl defintiions
#define SSL_MIN_GOOD_VERSION 0x002
#define SSL_MAX_GOOD_VERSION 0x304 // let's be optimistic here!
#define TLS_HANDSHAKE 22
#define TLS_CLIENT_HELLO 1
#define TLS_SERVER_HELLO 2
#define OFFSET_HELLO_VERSION 9
#define OFFSET_SESSION_LENGTH 43
#define OFFSET_CIPHER_LIST 44

char* ssl_version(u_short version) {

	static char hex[7];

	switch (version) {
		case 0x002: return "SSLv2";
		case 0x300: return "SSLv3";
		case 0x301: return "TLSv1";
		case 0x302: return "TLSv1.1";
		case 0x303: return "TLSv1.2";
	}
	snprintf(hex, sizeof(hex), "0x%04hx", version);

	return hex;
}
*/ // end of ssl definitions

/*
 *  * dissect/print packet
 *   
*/
void
got_packet(Domains *Dptr, const struct pcap_pkthdr *header, const u_char *packet)
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

	/* START OF SSL
	if (payload[0] != TLS_HANDSHAKE) {
		printf("Not a TLS handshake: 0x%02hhx\n", payload[0]);
		return;
	}

	if (size_payload < OFFSET_CIPHER_LIST + 3) { // at least one cipher + compression
		printf("TLS handshake header too short: %u bytes\n", size_tcp);
		return;
	}

	u_short proto_version = payload[1]*256 + payload[2];
	printf("%s ", ssl_version(proto_version));
	u_short hello_version = payload[OFFSET_HELLO_VERSION]*256 + payload[OFFSET_HELLO_VERSION+1];

	if (proto_version < SSL_MIN_GOOD_VERSION || proto_version >= SSL_MAX_GOOD_VERSION ||
		hello_version < SSL_MIN_GOOD_VERSION || hello_version >= SSL_MAX_GOOD_VERSION) {
		printf("%s bad version(s)\n", ssl_version(hello_version));
		return;
	}

	// skip session ID
	const u_char *cipher_data = &payload[OFFSET_SESSION_LENGTH];
	#ifdef LOG_SESSIONID
	if (cipher_data[0] != 0) {
		printf("SID[%hhu] ", cipher_data[0]);
	}
	#endif

	if (size_payload < OFFSET_SESSION_LENGTH + cipher_data[0] + 3) {
	printf("SessionID too long: %hhu bytes\n", cipher_data[0]);
	return;
	}

	cipher_data += 1 + cipher_data[0];

	switch (payload[5]) {
	case TLS_CLIENT_HELLO:
		printf("ClientHello %s ", ssl_version(hello_version));
		u_short cs_len = cipher_data[0]*256 + cipher_data[1];
		cipher_data += 2; // skip cipher suites length
		// FIXME: check for buffer overruns
		int cs_id;
		for (cs_id = 0; cs_id < cs_len/2; cs_id++)
			printf(":%02hhX%02hhX", cipher_data[2*cs_id], cipher_data[2*cs_id + 1]);
			printf(":\n");
			break;

	case TLS_SERVER_HELLO:
		printf("ServerHello %s ", ssl_version(hello_version));
		printf("cipher %02hhX%02hhX\n", cipher_data[0], cipher_data[1]);
		printf("%s\n", payload);
		break;

	default:
		printf("Not a Hello\n");
		return;
	}
	*/  //END OF SSL

/*
 *      * Print payload data; it might be binary, so don't just
 *           * treat it as a string.
 *                
*/
    if ((size_payload > 0) && (http = isGETPOST(payload))) {

		memset(host_clean, '\0', 32);
		memset(request_clean, '\0', 32);
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
		//memset(host_clean, '\0', 32);
		strncpy(host_clean, host+6, num_host-6);

		// send results in
		Tally(Dptr, &http, request_clean, host_clean);
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

int capture(pcap_t *handle, char *dev, char *errbuf, Domains *Dptr) {

	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	int num_packets = 0;           /* number of packets to capture */

	// catch Cntrl-C
	void mysighand(int signum) {
        if (signum == 2) {
            addstr("Catching SIGINT\nShutting Down\n");
			refresh();
			sleep(1);
            TearDown(Dptr);
			endwin();
            exit(1);
        }
	}

	// set control-c handler
	signal(SIGINT, mysighand);

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


	// Start up Ncurses and clear screen
	initscr();

	move(0,0);
	waddstr(stdscr, "Capture starting\n");
	refresh();


	/* now we can set our callback function */
	pcap_loop(handle, num_packets, (pcap_handler)got_packet, (u_char *)Dptr);

	/* cleanup */
	pcap_freecode(&fp);

	if (handle != NULL)
		pcap_close(handle);

	printf("\nCapture complete.\n");

	return(0);
}

int main(int argc, char *argv[])  {

	int i, j, k;
	pcap_t *handle = NULL;

	Domains *Dptr;

	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	
	// grab default interface
	dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	fprintf(stderr, "Device: %s\n", dev);

	// Initialize data structures
	Dptr = Initialize();

	//promiscuous(handle, dev, errbuf);
	capture(handle, dev, errbuf, Dptr);

/*
	// display results
	for (i = 0; i < Dptr->count; i++) {
		printf("Host: %s\t\tGET: %d\tPOST: %d\n", Dptr->dptr[i]->name, Dptr->dptr[i]->GET, Dptr->dptr[i]->POST);
		for (j = 0; j < Dptr->dptr[i]->num_requests; j++)
			//printf("%s\tcount: %d\n", Dptr->dptr[i]->requests[j]->url, Dptr->dptr[i]->requests[j]->count);
			printf("count: %d\t%s\n", Dptr->dptr[i]->requests[j]->count, Dptr->dptr[i]->requests[j]->url);
	}
	printf("\n");
	printf("number of domains: %d\n", ->Dptr->count);
*/

	// free up data structures
	TearDown(Dptr);

	// Cleanup Ncurses
	endwin();

	return(0);
}
