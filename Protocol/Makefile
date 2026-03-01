CC = gcc
CFLAGS = -Wall -O2

all: example example_messages test_uavlink

example: example.o uavlink.o monocypher.o
	$(CC) $(CFLAGS) -o example example.o uavlink.o monocypher.o

example_messages: example_messages.o uavlink.o monocypher.o
	$(CC) $(CFLAGS) -o example_messages example_messages.o uavlink.o monocypher.o

test_uavlink: test_uavlink.o uavlink.o monocypher.o
	$(CC) $(CFLAGS) -o test_uavlink test_uavlink.o uavlink.o monocypher.o -lm

example.o: example.c uavlink.h
	$(CC) $(CFLAGS) -c example.c

example_messages.o: example_messages.c uavlink.h
	$(CC) $(CFLAGS) -c example_messages.c

test_uavlink.o: test_uavlink.c uavlink.h monocypher.h
	$(CC) $(CFLAGS) -c test_uavlink.c

uavlink.o: uavlink.c uavlink.h monocypher.h
	$(CC) $(CFLAGS) -c uavlink.c

monocypher.o: monocypher.c monocypher.h
	$(CC) $(CFLAGS) -c monocypher.c

clean:
	rm -f *.o example example.exe example_messages example_messages.exe test_uavlink test_uavlink.exe

test: test_uavlink
	./test_uavlink
