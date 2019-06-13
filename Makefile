.PHONY: all
all: lztest

lztest: lztrace.c lztest.c
		$(CC) -c -Wall -g -finstrument-functions -rdynamic -o lztest.o lztest.c
		$(CC) -c -Wall -O3 -o lztrace.o lztrace.c
		$(CC) -o lztest lztest.o lztrace.o -ldl -lrt -ldw -lelf -lpthread

.PHONY: clean
clean:
		$(RM) -f lztest lztest.o lztrace.o

.PHONY: format
format:
		clang-format -i --style=file lztrace.c lztest.c
