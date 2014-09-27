CFLAGS=-g3 -lpcap

all: main

main: 
	cc $(CFLAGS) -o main main.c

clean:
	rm -rf main
