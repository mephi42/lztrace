override CFLAGS += -g -Wall -Wextra -Werror -std=c99

.PHONY: all
all: lztest

lztrace.o: lztrace.c
		$(CC) $(CFLAGS) -c -O3 -o lztrace.o lztrace.c

lztest.o: lztest.c
		$(CC) $(CFLAGS) -c -finstrument-functions -rdynamic -o lztest.o lztest.c

lztest: lztrace.o lztest.o
		$(CC) $(CFLAGS) -o lztest lztest.o lztrace.o -ldl -lrt -ldw -lelf -lpthread

.PHONY: test
test: lztest
		./lztest

.PHONY: clean
clean:
		$(RM) -f lztest lztest.o lztrace.o

.PHONY: format
format:
		clang-format -i --style=file lztrace.c lztest.c
