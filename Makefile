all: lztest

lztest: lztrace.c lztest.c
	gcc -c -Wall -g -finstrument-functions -rdynamic -o lztest.o lztest.c
	gcc -c -Wall -O3 -o lztrace.o lztrace.c
	gcc -o lztest lztest.o lztrace.o -ldl -lrt -ldw -lelf

clean:
	rm -f *.o lztest

