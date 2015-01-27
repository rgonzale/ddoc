//
//  ddoc.c
//
//  Tristan Gonzalez, ddoc, a web request statistics collector
//  Copyright (c) 2014-2015 Tristan Gonzalez. All rights reserved.
//  rgonzale@darkterminal.net
//
// credits to Tim Carstens for TCP/IP data structures from sniffer.c
// credits to Vito Ruiz for the name "ddoc"
//
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ncurses.h>
#include <signal.h>
#include <pthread.h>

/* program version */
float VERSION = 0.9;

/* default port */
#define PORT "port 80"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Starting number of struct domain pointers to hold before realloc() is called */
#define DOMAINS 2

/* Starting number of struct requeset pointers to hold before realloc is called */
#define REQUESTS 2

/* Starting number of struct ip pointers to hold before realloc is called */
#define IPS 2

/* Print Screen every number of seconds */
#define SECONDS 2

/* Definition for the ENTER key representing integer 10 */
#define ENTER 10

/* Macros for refreshing the pads */
#define PREFRESHP1HEAD prefresh(p1head, 0, 0, 0, 3, 0, columns);
#define PREFRESHP1INDEX prefresh(p1index, p1scrolltop, 0, 1, 0, part1rows, 1);
#define PREFRESHP1DOMAINS prefresh(p1domains, p1scrolltop, 0, 1, 3, part1rows, columns);
#define PREFRESHP2HEAD prefresh(p2head, 0, 0, 0, 0, 0, columns);
#define PREFRESHP2IPS prefresh(p2ips, 0, 0, 2, 0, 42, 30);
#define PREFRESHP2REQUESTS prefresh(p2requests, 0, 0, 2, 32, 42, columns);

/* Declaring Ncurses Pads */
WINDOW *p1head, *p1index, *p1domains, *p2head, *p2ips, *p2requests;

/* Declaring Ncurses Backup Pads to save state while paused */
WINDOW *p1domains_backup, *p1index_backup, *p2ips_backup, *p2requests_backup;

/* Defining Ncurses rows and columns */
int rows, columns, part1rows, part2rows, totalrowsp1, totalrowsp2;

/* Defining Ncurses scrolling variables */
int p1scrollbottom, p1scrolltop, p2scrollbottom, p2scrolltop, selection, position, input;
#define PREFRESHP1DOMAINSSCROLL prefresh(p1domains, p1scrolltop, 0, 1, 3, part1rows, columns);
#define PREFRESHP1INDEXSCROLL prefresh(p1index, p1scrolltop, 0, 1, 0, part1rows, 1);

/* Domain string and boolean int for switching between part1 and part2 */
struct Domain *part2domain;
int usePart2;
int Pause;
int Shutdown;
int realtime;
int useFilter;

/* filter buffer */
char Filter[80];

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
	int seconds;  // rate to print to screen
	u_int count;  // number of domains
	u_int size;   // size of domain pointer array
	struct Domain **dptr;  // array of pointers pointing to struct Domain
	char *interface;
	struct bpf_program *fp;
	pcap_t *handle;
	char port[11]; // buffer to hold port number
};

typedef struct Domains Domains;

/*
 * struct to store data on domain
 */
struct Domain {
		u_int GET, POST;
		u_int num_requests;
		u_int total_requests;
		u_int num_ips;
		char name[64];
		u_int request_size;
		struct Request **requests;
		u_int ip_size;
		struct IP **ips;
};

typedef struct Domain Domain;

/*
 * struct to store requests about a domain
 */
struct Request {
		u_int count;	
		char url[128];
};

typedef struct Request Request;

/*
 * struct to store IPs
 */
struct IP {
	u_int count;
	char ip[16];
};

typedef struct IP IP;

/*
 * allocates and creates a domain struct
 */
void AddDomain(Domains *Dptr, char *host)
{
	int count = 0, size = 0;
	Domain **tmp;
	count = Dptr->count;
	size = Dptr->size;

	// if the number of struct Domains is the same as number of struct pointers in the array then realloc array by factor of 2
	if (count == size) {
		tmp = (Domain **) realloc(Dptr->dptr, (sizeof(Domain *) * size) * 2);
		if (tmp == NULL) {
	    	fprintf(stderr, "Realloc failed\n");
        	exit(1);
		}
		else
			Dptr->dptr = tmp;

		tmp = NULL;
		size *= 2;
		Dptr->size = size;
	}

	// allocate memory for 1 struct domain
	Domain *domain = calloc(1, sizeof(struct Domain));
	
	Dptr->dptr[count] = domain;
	Dptr->count++;
	strncpy(Dptr->dptr[count]->name, host, 64);
	Dptr->dptr[count]->GET = 0;
	Dptr->dptr[count]->POST = 0;
	Dptr->dptr[count]->num_requests = 0;
	Dptr->dptr[count]->total_requests = 0;

	// allocate memory for array of pointers to struct IP
	Dptr->dptr[count]->ips = (IP **) calloc(IPS, sizeof(IP *));
	Dptr->dptr[count]->ip_size = IPS;

	// allocate memory for array of pointers to struct request
	Dptr->dptr[count]->requests = (Request **) calloc(IPS, sizeof(Request *));
	Dptr->dptr[count]->request_size = REQUESTS;

	return;
}

/*
 * add new request
 */
void AddRequest(Domains *Dptr, int *domain_index, int *request_index, char *req)
{
	int num_requests = 0, size = 0;
	Request **tmp;

	size = Dptr->dptr[*domain_index]->request_size;
	num_requests = Dptr->dptr[*domain_index]->num_requests;

	// if the number of struct Request is the same as number of struct pointers in the array then realloc array by factor of 2
	if (num_requests == size) {
		tmp = (Request **) realloc(Dptr->dptr[*domain_index]->requests, (sizeof(Request *) * size) * 2);
		if (tmp == NULL) {
			fprintf(stderr, "Failed to realloc\n");
			exit(1);
		}
		else
			Dptr->dptr[*domain_index]->requests = tmp;	

		tmp = NULL;
		size *= 2;
		Dptr->dptr[*domain_index]->request_size = size;
	}

	// allocate memory for 1 struct Request
	Request *request = calloc(1, sizeof(struct Request));

	Dptr->dptr[*domain_index]->requests[*request_index] = request;
	Dptr->dptr[*domain_index]->num_requests++;
	Dptr->dptr[*domain_index]->total_requests++;
	Dptr->dptr[*domain_index]->requests[*request_index]->count = 0;
	Dptr->dptr[*domain_index]->requests[*request_index]->count++;
	strncpy(Dptr->dptr[*domain_index]->requests[*request_index]->url, req, 128);
	
	return;
}

/*
 * increment an existing request
 */
void IncrementRequest(Domains *Dptr, int *domain_index, int *request_index, const char *req)
{
	Dptr->dptr[*domain_index]->total_requests++;
	Dptr->dptr[*domain_index]->requests[*request_index]->count++;
	
	return;
}

/*
 * add new ip
 */
void AddIP(Domains *Dptr, int *domain_index, int *ip_index, char *ip)
{
	int size = 0, num_ips = 0;
	size = Dptr->dptr[*domain_index]->ip_size;
	num_ips = Dptr->dptr[*domain_index]->num_ips;

	IP **tmp;

	// if the number of struct IP is the same as number of struct pointers in the array then realloc array by factor of 2
	if (num_ips == size) {
		tmp = (IP **) realloc(Dptr->dptr[*domain_index]->ips, (sizeof(IP *) * size) * 2);
		if (tmp == NULL) {
			fprintf(stderr, "Failed to realloc\n");
			exit(1);
		}
		else
			Dptr->dptr[*domain_index]->ips = tmp;

		tmp = NULL;
		size *= 2;
		Dptr->dptr[*domain_index]->ip_size = size;
	}

	// allocate memory for 1 struct IP
	IP *ipaddress= calloc(1, sizeof(struct IP));

	Dptr->dptr[*domain_index]->ips[*ip_index] = ipaddress;
	Dptr->dptr[*domain_index]->ips[*ip_index]->count = 0;
	Dptr->dptr[*domain_index]->ips[*ip_index]->count++;
	strncpy(Dptr->dptr[*domain_index]->ips[*ip_index]->ip, ip, 16);
	Dptr->dptr[*domain_index]->num_ips++;
	
	return;
}

/*
 * increment an existing ip
 */
void IncrementIP(Domains *Dptr, int *domain_index, int *ip_index, const char *ip)
{
	Dptr->dptr[*domain_index]->ips[*ip_index]->count++;
	
	return;
}

/*
 * checks if ip exists
 */
int CheckifIPExists(Domains *Dptr, int *domain_index, char *ip)
{
	int i;

	for (i = 0; i < Dptr->dptr[*domain_index]->num_ips; i++) {
		if (strncmp(Dptr->dptr[*domain_index]->ips[i]->ip, ip, strlen(ip)) == 0)
			return i;
	}
	return -1;
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
int CheckifRequestExists(Domains *Dptr, int *domain_index, const char *request)
{
	int i;

	for (i = 0; i < Dptr->dptr[*domain_index]->num_requests; i++) {
		if (strncmp(Dptr->dptr[*domain_index]->requests[i]->url, request, strlen(request)) == 0)
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
 * sort Domain function
 */
int sortDomains(Domains *Dptr, int *domain_index)
{
	int i, index = -1;
	struct Domain *tmp;
	for (i = *domain_index; i > 0; i--) {
		if (Dptr->dptr[i]->total_requests > Dptr->dptr[i-1]->total_requests) {
			tmp = Dptr->dptr[i];
			Dptr->dptr[i] = Dptr->dptr[i-1];
			Dptr->dptr[i-1] = tmp;	
			index = i-1;
		}
	}
	if (index != -1)
		return index;
	else
		return *domain_index;
}

/*
 * sort Request function
 */
int sortRequests(Domain *dptr, int *request_index)
{
	int i, index = -1;
	struct Request *tmp;
	for (i = *request_index; i > 0; i--) {
		if (dptr->requests[i]->count > dptr->requests[i-1]->count) {
			tmp = dptr->requests[i];
			dptr->requests[i] = dptr->requests[i-1];
			dptr->requests[i-1] = tmp;	
			index = i-1;
		}
	}
	if (index != -1)
		return index;
	else
		return *request_index;
}

/*
 * sort IP function, only compares elements in array that are before it
 */
int sortIPs(Domain *dptr, int *ip_index)
{
	int i, index = -1;
	struct IP *tmp;
	for (i = *ip_index; i > 0; i--) {
		if (dptr->ips[i]->count > dptr->ips[i-1]->count) {
			tmp = dptr->ips[i];
			dptr->ips[i] = dptr->ips[i-1];
			dptr->ips[i-1] = tmp;	
			index = i-1;
		}
	}
	if (index != -1)
		return index;
	else
		return *ip_index;
}

/*
 * function to display intro screen
 */
void DisplayIntro(Domains *Dptr)
{
	clear();
	move(0,0);
	printw("rows = %d\ncolumns = %d\n", rows, columns);
	printw("Capture starting using %s\n", Dptr->interface);
	refresh();
	sleep(1);
	wmove(p1index, 0, 0);
	waddstr(p1index, "->");
}

/*
 * function to erase all data from the screen
 */
void EraseAll()
{
	werase(p1index);
	werase(p1domains);
	werase(p2ips);
	werase(p2requests);
	clear();	
}

/*
 * function to refresh all pads
 */
void RefreshAll()
{
	PREFRESHP1DOMAINS;
	PREFRESHP1INDEX;
	PREFRESHP2IPS;
	PREFRESHP2REQUESTS;
	refresh();
}

/*
 * function to refresh pads in Part1
 */
void Part1Refresh()
{
	PREFRESHP1INDEX;
	PREFRESHP1DOMAINS;
	clear();
	refresh();
}

/*
 * function to refresh pads in Part2
 */
void Part2Refresh()
{
	PREFRESHP2HEAD;
	PREFRESHP2IPS;
	PREFRESHP2REQUESTS;
	clear();
	refresh();
}

/*
 * function to resize Part1
 */
void Part1Resize()
{
	delwin(p1head);
	delwin(p1index);
	delwin(p1domains);
	p1head = newpad(1, columns-3);
	p1index = newpad(totalrowsp1*2, 2);
	p1domains = newpad(totalrowsp1*2, columns-3);

	totalrowsp1 *= 2;
	PREFRESHP1HEAD;
	PREFRESHP1DOMAINS;
	PREFRESHP1INDEX;
}

/*
 * function to resize Part2
 */
void Part2Resize()
{
	delwin(p2head);
	delwin(p2ips);
	delwin(p2requests);
	p2head = newpad(1, columns);
	p2ips = newpad((totalrowsp2*2)-2, 31);
	p2requests = newpad((totalrowsp2*2)-2, columns-32);

	totalrowsp2 *= 2;
	PREFRESHP2HEAD;
	PREFRESHP2IPS;
	PREFRESHP2REQUESTS;;
}

/*
 * Ncurses Part1 - Summary of Domains
 */
void NcursesPart1(Domains *Dptr)
{
	int i;


	// clear up screen
	werase(p2head);
	werase(p2ips);
	werase(p2requests);
	Part2Refresh(Dptr);

	// print header
	wmove(p1head, 0, 0);
	
	if (Pause) waddstr(p1head, "Total\t\tGET\t\tPOST\t\tDomain\t\t*Paused*\n");
	else waddstr(p1head, "Total\t\tGET\t\tPOST\t\tDomain\n");

	PREFRESHP1HEAD;

	// move to the top left corner and output Domain Summary Statistics (Part 1)
	wmove(p1domains, 0, 0);
	for (i = 0; i < Dptr->count; i++)
		wprintw(p1domains, "%d\t\t%d\t\t%d\t\t%s\n", 	Dptr->dptr[i]->total_requests, 
														Dptr->dptr[i]->GET, 
														Dptr->dptr[i]->POST, 
														Dptr->dptr[i]->name);

	PREFRESHP1DOMAINS;

	// refresh index arrow
	PREFRESHP1INDEX;
}

/*
 * Ncurses Part2 - Summary of Domain
 */
void NcursesPart2(Domain *dptr)
{
	int i;

	// clear up screen
	werase(p1head);
	werase(p1index);
	werase(p1domains);
	Part1Refresh();

	// move to the top left of p2requests pad 
	wmove(p2head, 0, 0);
	if (Pause)
		wprintw(p2head, "IPs:count  *Paused*\t%s\t\tGET: %d\t\tPOST: %d\t\tTotal Requests: %d\n", 
											dptr->name,
											dptr->GET,
											dptr->POST,
											dptr->total_requests);
	else
		//wprintw(p2head, "IPs:count\t\t%s\t\tGET: %d\t\tPOST: %d\t\tTotal Requests: %d\n", 
		wprintw(p2head, "IPs:count\t\t%s\t\tGET: %d\t\tPOST: %d\t\tTotal Requests: %d num_requests: %d, totalrowsp2: %d\n", 
											dptr->name,
											dptr->GET,
											dptr->POST,
											dptr->total_requests, dptr->num_requests, totalrowsp2);

	PREFRESHP2HEAD;

	// move to top left of p2ips pad
	wmove(p2ips, 0, 0);

	for (i = 0; i < dptr->num_ips; i++)
		wprintw(p2ips, "%s: %d\n",	dptr->ips[i]->ip,
									dptr->ips[i]->count);	

	PREFRESHP2IPS;

	// output URLs
	wmove(p2requests, 0, 0);
	for (i = 0; i < dptr->num_requests; i++) {
		if (useFilter == 1) {
			if (filterURL(dptr->requests[i]->url) == 1)
				wprintw(p2requests, "count: %d\t%s\n",	dptr->requests[i]->count,
														dptr->requests[i]->url);	
		}
		else 
			wprintw(p2requests, "count: %d\t%s\n",	dptr->requests[i]->count,
													dptr->requests[i]->url);	
	}

	PREFRESHP2REQUESTS;
}	

/*
 * executes accounting
 */
void Tally(Domains *Dptr, int *http, char *request, char *host, char *ip)
{
	int domain_index, request_index, ip_index;
	
	domain_index = 0;
	request_index = 0;
	ip_index = 0;

	domain_index = GetDomainIndex(Dptr, host);

	/* new code to try */
	if (domain_index == -1) {
		domain_index = Dptr->count;
		AddDomain(Dptr, host);
	}

	if (*http == 1) 		
		Dptr->dptr[domain_index]->GET++;
	else if (*http == 2)
		Dptr->dptr[domain_index]->POST++;

	request_index = CheckifRequestExists(Dptr, &domain_index, request);

	// if request not found set to -1 and set to num_requests when adding a new one
	if (request_index == -1) {
		request_index = Dptr->dptr[domain_index]->num_requests;
		
		AddRequest(Dptr, &domain_index, &request_index, request);	
	}
	else {
		IncrementRequest(Dptr, &domain_index, &request_index, request);
	}

	ip_index = CheckifIPExists(Dptr, &domain_index, ip);

	// if ip not found set to -1 and set to num_ips when adding a new one
	if (ip_index == -1) {
		ip_index = Dptr->dptr[domain_index]->num_ips;

		AddIP(Dptr, &domain_index, &ip_index, ip);
	}
	else {
		IncrementIP(Dptr, &domain_index, &ip_index, ip);
	}

	// sort the domains
	if (Dptr->count > 1 && domain_index != 0)
		domain_index = sortDomains(Dptr, &domain_index);

	// sort the request
	if (Dptr->dptr[domain_index]->num_requests > 1)
		request_index = sortRequests(Dptr->dptr[domain_index], &request_index);

	// sort the IP
	if (Dptr->dptr[domain_index]->num_ips > 1)
		ip_index = sortIPs(Dptr->dptr[domain_index], &ip_index);

	// add more rows if need be
	if (Dptr->count >= totalrowsp1 - 1)
		Part1Resize();

	if (Dptr->dptr[domain_index]->num_requests >= totalrowsp2)
		Part2Resize();

	//if (Pause == 1) return;
	if (Pause || Shutdown)
		return;

	if (realtime == 1) {

		// call main update ncurses function
		if (usePart2 == 1)
			NcursesPart2(part2domain);
		else
			NcursesPart1(Dptr);
	}	

	return;
}
	
/*
 * Initializes main pointer to data structures
 */
Domains *Initialize()
{
	// allocate memory for Dptr
	Domains *Dptr = calloc(1, sizeof(Domains));
	Dptr->count = 0;
	Dptr->size = 0;
	Dptr->interface = NULL;
	bzero(Dptr->port, 11);
	strncpy(Dptr->port, PORT, 10);
	Dptr->port[10] = '\0';
	Dptr->seconds = SECONDS;

	// allocate memory for array of pointers to struct domain
	Dptr->dptr = (Domain **) calloc(DOMAINS, sizeof(Domain *));

	Dptr->size = DOMAINS;

	return Dptr;
}

/*
 * Frees up all the data structures
 */
void TearDown(Domains *Dptr)
{
	int i, j, ips = 0, size = 0, count = 0;

	size = Dptr->size;
	count = Dptr->count;
	
	for (i = 0; i < Dptr->count; i++)
		for (j = 0; j < Dptr->dptr[i]->num_requests; j++)
			free(Dptr->dptr[i]->requests[j]);

	for (i = 0; i < Dptr->count; i++)
		for (j = 0; j < Dptr->dptr[i]->num_ips; j++)
			free(Dptr->dptr[i]->ips[j]);

	for (i = 0; i < count; i++)
		free(Dptr->dptr[i]);

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
 * dissect/print packet
 */
void got_packet(Domains *Dptr, const struct pcap_pkthdr *header, const u_char *packet)
{

	int http;								/* HTTP method GET/POST */
	char *request;							/* the actual web request url */
	int num_request = 0, num_host = 0;		/* bytes to copy only request and host */
	char request_clean[128];					 
	char *host;								/* start of Host header */
	char host_clean[64];					/* start of Host header not including 'Host: ' */
	char *address;  						/* ip address */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;


    /* define ethernet header */
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
 */
    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

/*
 *      * Print payload data; it might be binary, so don't just
 *           * treat it as a string.
 */
    if ((size_payload > 0) && (http = isGETPOST(payload))) {

		// zero out buffers
		memset(host_clean, '\0', 64);
		memset(request_clean, '\0', 128);

		// request
		num_request = strcspn(payload, "\r");
	
		// if request is greather than 127 bytes copy 127 bytes into it and adda null byte '\0' at the end
		if (num_request > 127) {
			strncpy(request_clean, payload, 127);
			request_clean[127] = '\0';
		}
		else
			strncpy(request_clean, payload, num_request);

		// host header
		host = strstr(payload, "Host: ");
		if (host == NULL)
			snprintf(host_clean, 5, "NULL");
		else {
			num_host = strcspn(host, "\r");
		
			// if host is greather than 63 bytes copy 63 bytes into it and adda null byte '\0' at the end
			// "+6" by exclude "Host: "
			if (num_host > 63) {
				strncpy(host_clean, host+6, 63);
				host_clean[63] = '\0';
			}
			else
				strncpy(host_clean, host+6, num_host-6);
			
		}

		address = inet_ntoa(ip->ip_src);
		if (*address > 15)
			address[15] = '\0';
		// send results in
		Tally(Dptr, &http, request_clean, host_clean, address);
	}

	return;
}

/*
 * function to put interface in promiscuous/capture mode
 */
int promiscuous(pcap_t *handle, char *dev, char *errbuf)
{

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

/*
 * main capture  function
 */
int capture(pcap_t *handle, char *dev, char *errbuf, Domains *Dptr) {

	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[11];	/* The filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	int num_packets = 0;           /* number of packets to capture */

	bzero(filter_exp, 11);
	strncpy(filter_exp, Dptr->port, strlen(Dptr->port));
	if (filter_exp[10] != '\0');
		filter_exp[10] = '\0';

	// catch Cntrl-C
	void mysighand(int signum) {
        if (signum == 2) {
			move(0, 0);
			clear();
			refresh();
            addstr("Inga\nCatching SIGINT\nShutting Down\n");
			refresh();
			sleep(1);
            TearDown(Dptr);
			NcursesExit();
            exit(1);
        }
	}

	// set control-c handler
	signal(SIGINT, mysighand);

	// fire up Ncurses
	NcursesInit(Dptr);

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

	// set handle and fp to Dptr so that CleanExit() can free them
	Dptr->fp = &fp;
	Dptr->handle = handle;

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, (pcap_handler)got_packet, (u_char *)Dptr);
	
	/* cleanup */
	pcap_freecode(&fp);

	if (handle != NULL)
		pcap_close(handle);

	// shut down Ncurses
	CleanExit(Dptr);

	printf("\nCapture complete.\n");

	return(0);
}

/*
 * function to start up Ncurses
 */
int NcursesInit(Domains *Dptr) 
{
	
	// Start up Ncurses
	initscr();

	// turn off cursor
	curs_set(0);

	// enable colors
	if (has_colors() == TRUE)
		start_color();

	// create black and white pair
	init_pair(1, COLOR_BLACK, COLOR_WHITE);
	init_pair(2, COLOR_WHITE, COLOR_BLACK);

	// get number of rows and columns for current session
	getmaxyx(stdscr, rows, columns);

	/* initialize pads
	 * p1head = Header
	 * p1index = User Input
	 * p1domains = Full summary of domains and their requests
	 * p2head = Header
	 * p2ips = domains specific stats IP
	 * p2requests = domain specific stats URLs
	 */	
	p1head = newpad(1, columns-3);
	p1index = newpad(rows-1, 2); // hold indexes
	p1domains = newpad(rows-1, columns-3); // hold Summary of Domains
	p2head = newpad(1, columns);
	p2ips = newpad(rows-2, 31);
	p2requests = newpad(rows-2, columns-32);
	totalrowsp1 = rows;

	// set dynamic rows variable for scrolling and to resize rows in Part1Resize() and Part2Resize()
	part1rows = rows-1;
	p1scrollbottom = part1rows;
	part2rows = rows-2;
	totalrowsp2 = part2rows;
	
	DisplayIntro(Dptr);
}

/*
 * function to free up all resources properly
 */
CleanExit(Domains *Dptr) 
{

	werase(p1domains);
	PREFRESHP1DOMAINS;
	werase(p1index);
	PREFRESHP1INDEX;
	werase(p2requests);
	PREFRESHP2REQUESTS;
	werase(p2ips);
	PREFRESHP2IPS;
	move(0, 0);
    addstr("Shutting Down\n");
	refresh();
	sleep(1);
    
	NcursesExit();

	if (Dptr->handle != NULL)
		pcap_close(Dptr->handle);

	TearDown(Dptr);

	// pthread exiting program
	exit(0);
}

/*
 * function to shut down Ncurses
 */
int NcursesExit() 
{

	// Cleanup Ncurses
	delwin(p1head);
	delwin(p1index);
	delwin(p1domains);
	delwin(p2head);
	delwin(p2ips);
	delwin(p2requests);
	endwin();
}

/*
 * function to resize screen when window has been resized
 */
void ScreenResize()
{
	getmaxyx(stdscr, rows, columns);

	// recalibrate numbers of rows in Part1 and Part2
	part1rows = rows-1;
	part2rows = rows-2;
}

/* 
 * function to have thread run for user input
 */
void UserInput(Domains *Dptr) 
{
	int status = 0;

	selection = 0;
	position = 0;
	input = 0;
	useFilter = 0;
	
	int ret1 = 0;
	
	// set scrolling variables
	p1scrolltop = 0;
	p2scrolltop = 0;

	// turn off cursor
	curs_set(0);

	PREFRESHP1INDEX;
	
	do {
		input = getchar();

		switch(input) {
			case 'e': // switch to part 2 for domain
				if (usePart2 == 0) {
					part2domain = Dptr->dptr[selection];
					usePart2 = 1;
				}
				break;
			case 'f': // add filter
				if (usePart2 == 0) break;
				if (useFilter == 0) {
					Pause = 1;
					useFilter = 1;
					werase(p2head);
					PREFRESHP2HEAD;
					wmove(p2head, 0, 0);
					wprintw(p2head, "Enter filter: ");
					wmove(p2head, 0, 15);
					prefresh(p2head, 0, 0, 0, 0, 0, columns);
					mvgetnstr(0, 14, Filter, 80);
					werase(p2head);
					werase(p2ips);
					werase(p2requests);
					Part2Refresh(Dptr);
					Pause = 0;
				}
				else {
					useFilter = 0;
					clear();
					move(0, 0);
					addstr("Removing filter");
					refresh();
					ScreenResize();
					sleep(1);
				}
				break;
				case 'i': // switch to part 1
				if (usePart2 == 1) {
					usePart2 = 0;
					useFilter = 0;
					part2domain = NULL;
					position = 0;
					selection = 0;
					p1scrolltop = 0;
					p1scrollbottom = part1rows;
					Part2Refresh(Dptr);
					//NcursesPart1(Dptr);
				}
				break;
			case 'j': // move down
				// if at the bottom of the screen
				// use Part1
				if ((selection < Dptr->count-1) && (usePart2 == 0)) {
					if (position == p1scrollbottom-1) {
						wmove(p1index, selection, 0);
						werase(p1index);
						p1scrolltop++;	
						p1scrollbottom++;
						selection++;
						position++;
						wmove(p1index, selection, 0);
						waddstr(p1index, "->");
						PREFRESHP1DOMAINSSCROLL;
						PREFRESHP1INDEXSCROLL;
					}
					else {
						wmove(p1index, position, 0);
						werase(p1index);
						position++;
						selection++;
						wmove(p1index, position, 0);
						waddstr(p1index, "->");
						PREFRESHP1INDEX;
					}
				}
				break;
			case 'k': // move up
				// if at the top of the screen
				// usePart1
				if ((selection > 0) && (usePart2 == 0)) {
					if (position == p1scrolltop) {
						wmove(p1index, selection, 0);
						werase(p1index);
						p1scrolltop--;	
						p1scrollbottom--;
						selection--;
						position--;
						wmove(p1index, selection, 0);
						waddstr(p1index, "->");
						PREFRESHP1DOMAINSSCROLL;
						PREFRESHP1INDEXSCROLL;
					}
					else {
						wmove(p1index, position, 0);
						werase(p1index);
						position--;
						selection--;
						wmove(p1index, position, 0);
						waddstr(p1index, "->");
						PREFRESHP1INDEX;
					}
				}
		
				break;
			case 'p': // pause/resume
				// Pausing
				if (Pause == 0) {
					Pause = 1;
					
					// if packet capture hasn't started
					if (Dptr->count == 0) {
						clear();
						move(0, 0);
						addstr("Paused");
						refresh();
					}
					// packet capture has already started
					else {
						if (usePart2)
							NcursesPart2(part2domain);
						else
							NcursesPart1(Dptr);
					}
				}
				// Unpausing
				else {
					Pause = 0;
					// if packet capture hasn't started
					if (Dptr->count == 0)
						DisplayIntro(Dptr);
					// packet capture has already started
					else {
						if (usePart2)
							NcursesPart2(part2domain);
						else
							NcursesPart1(Dptr);
					}
				}
				break;
			case 'r': // screen resize
				clear();
				move(0, 0);
				addstr("Resizing screen");
				refresh();
				ScreenResize();
				sleep(1);
				break;
			default:
				break;
		}
	} while (input != 'q');
		Shutdown = 1;
		werase(p1index);
		PREFRESHP1INDEX;
		sleep(1);
		CleanExit(Dptr);
}

/*
 * function to have thread switch between parts
 */
void PartSwitcher(Domains *Dptr)
{
	int status = 0;
	for(;;) {
		do {
			sleep(1);
		} while (usePart2 == 0);
			NcursesPart2(part2domain);

		do {
			sleep(1);
		} while (usePart2 == 1);
			wmove(p1index, position, 0);
			waddstr(p1index, "->");
			PREFRESHP1INDEX;
			NcursesPart1(Dptr);
	}
}

/*
 * function to print to the screen every 2 seconds
 */
void PrintScreen(Domains *Dptr)
{
	int status = 0;

	for(;;) {
		sleep(Dptr->seconds);
		if (Shutdown == 1) pthread_exit(&status);
		if (Pause == 0) {
			if (usePart2 == 0) {
				NcursesPart1(Dptr);
			}
			else
				NcursesPart2(part2domain);
		}
	}
}

/*
 * function to filter out URLs
 */
int filterURL(char *url)
{
	if (strstr(url, Filter)) return 1;
	else return 0;
}

/*
 * function to print command usage
 */
void PrintUsage(char **argv, Domains *Dptr)
{
	fprintf(stderr, "%s version %.1f\n", argv[0], VERSION);
	fprintf(stderr, "Usage: %s [-i <interface(default eth0)>] [-n <update screen per seconds(1-120, default 2)>] [-p <port(1-65535, default 80)>] [-r realtime(screen updates per packet)]\n\n", argv[0]);
	fprintf(stderr, "Runtime Commands\n");
	fprintf(stderr, "p - pause screen to highlight text for copying\n");
	fprintf(stderr, "q - quit program\n");
	fprintf(stderr, "r - resize screen\n\n");


	fprintf(stderr, "Master mode\n");
	fprintf(stderr, "e - enter Domain mode for selected domain\n");
	fprintf(stderr, "j/k - move up and down domain list\n\n");

	fprintf(stderr, "Domain mode\n");
	fprintf(stderr, "f - add filter/release filter\n");
	fprintf(stderr, "i - back out to Master mode\n");
	free(Dptr);
	exit(1);
}

/*
 * function to parse through command line arguments
 */
void ParseArguments(int *argc, char **argv, Domains *Dptr)
{
	int opt = 0;

	while ((opt = getopt(*argc, argv, "hi:n:p:r")) != -1) {
		switch(opt) {
    		case 'i':
    			Dptr->interface = optarg;
    			break;
			case 'h':
				PrintUsage(argv, Dptr);
				break;
			case 'n':
				if ((atoi(optarg) > 0) && (atoi(optarg) < 121)) {
					Dptr->seconds = atoi(optarg);
					break;
				}
				else
					PrintUsage(argv, Dptr);
			case 'p':
				if ((atoi(optarg) > 0) && (atoi(optarg) < 65536)) {
					strncpy(Dptr->port+5, optarg, 5);
					if (Dptr->port[10] != '\0');
						Dptr->port[10] = '\0';
				}
				else
					PrintUsage(argv, Dptr);
				break;
			case 'r':
				realtime = 1;
				break;
    		case '?':  // if user does not use required argument with an option
    			if (optopt == 'i') {
					PrintUsage(argv, Dptr);
  				} else {
					PrintUsage(argv, Dptr);
  				}
				if (optopt == 'n') {
					PrintUsage(argv, Dptr);
  				} else {
					PrintUsage(argv, Dptr);
  				}
				if (optopt == 'p') {
					PrintUsage(argv, Dptr);
  				} else {
					PrintUsage(argv, Dptr);
  				}
  				break;
 		}
 	}
	return;
}

int main(int argc, char *argv[])  {

	int i, j, k;

	// main capture pointer
	pcap_t *handle = NULL;

	// thread variables
	pthread_t user_input, part_switcher, print_screen;

	// have Part1 ready to display
	usePart2 = 0;

	// have pause turned off
	Pause = 0;

	// set realtime to 0
	realtime = 0;

	// initialize mutex
	pthread_mutex_t mylock = PTHREAD_MUTEX_INITIALIZER;

	// variables for capture()
	char errbuf[PCAP_ERRBUF_SIZE];

	// main data structure parent
	Domains *Dptr;

	// Initialize data structures
	Dptr = Initialize();

	// parse arg grab interface nam
	if (argc > 1) {
		ParseArguments(&argc, argv, Dptr);
		if (Dptr->interface == NULL)
			Dptr->interface = pcap_lookupdev(errbuf);
	}
	else {
		// grab default interface
		Dptr->interface = pcap_lookupdev(errbuf);
	}

	if (Dptr->interface == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	fprintf(stderr, "Device: %s\n", Dptr->interface);

	// start up user input thread
	pthread_create (&user_input, NULL, (void *) &UserInput, (void *) Dptr);

	// start up part_switcher thread
	pthread_create (&part_switcher, NULL, (void *) &PartSwitcher, (void *) Dptr);

	// start the Print Screen thread
	if (realtime == 0)
		pthread_create (&print_screen, NULL, (void *) &PrintScreen, (void *) Dptr);

	//promiscuous(handle, dev, errbuf);
	capture(handle, Dptr->interface, errbuf, Dptr);

	// free up data structures
	TearDown(Dptr);

	return(0);
}
