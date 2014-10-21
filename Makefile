CFLAGS=-g3 -lpcap -lncurses

all: main

main: 
	cc $(CFLAGS) -o main main.c

clean:
	rm -rf main
