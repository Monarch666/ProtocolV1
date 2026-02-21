CC = gcc
CFLAGS = -Wall -O2

all: example

example: example.o uavlink.o monocypher.o
	$(CC) $(CFLAGS) -o example example.o uavlink.o monocypher.o

example.o: example.c uavlink.h
	$(CC) $(CFLAGS) -c example.c

uavlink.o: uavlink.c uavlink.h monocypher.h
	$(CC) $(CFLAGS) -c uavlink.c

monocypher.o: monocypher.c monocypher.h
	$(CC) $(CFLAGS) -c monocypher.c

clean:
	rm -f *.o example example.exe
