### Introduction

Ever get a server with a number of domains.  Customer asks which domain is getting hit the most.  You use httpry and apachectl fullstatus but neither offer an accurate overall view.  Reviewing log files takes time.  ddoc, a web traffic accounting tool, uses packet capture to build an accounting of the number of GET and POST requests for a domain as the HTTP packets come in.  ddoc prioritizes the domains by the number of total requests placing the domain with the highest total requests on top.  For more detailed information you can select a domain using the ncurses  platform.  The detailed information page will show you the IPs hitting the domain and the URLs being requested all prioritized by the number of hits.  Say you just wanted to see only the POST requests.  You can add a filter to just show the POST requests.  If you need to copy a URL, IP, domain, etc, you can pause the screen so that the screen will not update.  This will allow you to copy whatever you need from the screen.

In summary, ddoc helps identify which domain is getting hit the most, which URL is being requested the most, and which IP is hitting the domain the most in a very short amount of time.  As of now ddoc works on RedHat/CentOS servers.

### Notes

1. Keep in mind that ddoc uses packet capture, so you may see domains and URLs that do not exist on the server but were in the HTTP request.  If a packet includes data that is not within the Ascii range, gibberish will show up on the screen.
2. ddoc grabs the Host header from an HTTP packet and uses that as the name of the domain.  You may see NULL in which case no Host header was included.
3. The realtime mode updates the screen each time a HTTP packet is received.  It looks very cool but can DOS a server.
4. If you want to compile the src/main.c file alone I have been using

gcc -o ddoc -lpthread -ncurses -lpcap main.c

### For some reason Debian/Ubuntu servers have trouble linking the shared libraries.  You can get around this by doing

1. cd src
2. cpp main.c > main.i
3. gcc -S main.i
4. gcc -o ddoc main.o -lpthread -lpcap -lncurses

Or copy a paste for a fast-track install

1. apt-get update
2. apt-get install -y libpcap-dev libncurses5-dev
3. cd /home/rack
4. wget darkterminal.net/ddoc.c
5. cpp ddoc.c > ddoc.i
6. gcc -S ddoc.i
7. as ddoc.s -o ddoc.o
8. gcc -o ddoc ddoc.o -lpthread -lpcap -lncurses


### Where to Get it

1. git clone https://github.com/rgonzale/ddoc.git
2. cd ddoc
3. ./configure --prefix=/usr/local
4. make
5. make install

### Dependencies

1. libpcap-devel (RedHat/CentOS), libpcap-dev (Debian/Ubuntu)
2. ncurses-devel (RedHat/CentOS), libncurses5-dev (Debian/Ubuntu)
3. gcc
4. make

### Instructions

Usage: ddoc [-i <interface(default eth0)>] [-n <update screen per seconds(1-120, default 2)>] [-p <port(1-65535, default 80)>] [-r realtime(screen updates per packet)]

### Runtime Commands

p - pause screen to highlight text for copying

q - quit program

### Master mode

e - enter Domain mode for selected domain

j/k - move up and down domain list

### Domain mode

f - add filter/release filter

i - back out to Master mode

### Credits

credits to Tim Carstens for TCP/IP data structures from sniffer.c
credits to Vito Ruiz for the sorting algorithm and the name "ddoc"

### Contact

If there are any bugs or issues you can contact me

Ruben "Tristan" Gonzalez

ruben.gonzalez@rackspace.com

rgonzale@darkterminal.net

Hope you all enjoy the tool!
