CC = gcc
CFLAGS = -Wall -O2

# Source files
CORE_SRC = uavlink.c uavlink_fast.c uavlink_compress.c uavlink_hw_crypto.c monocypher.c

# Platform-specific flags
ifeq ($(OS),Windows_NT)
    LDFLAGS = -lws2_32 -lm
    EXT = .exe
else
    LDFLAGS = -lm
    EXT =
endif

all: benchmark receiver simulator

benchmark: uavlink_benchmark.c $(CORE_SRC)
	$(CC) $(CFLAGS) -o uavlink_benchmark$(EXT) uavlink_benchmark.c $(CORE_SRC) $(LDFLAGS)

receiver: gcs_receiver.c $(CORE_SRC)
	$(CC) $(CFLAGS) -o gcs_receiver$(EXT) gcs_receiver.c $(CORE_SRC) $(LDFLAGS)

simulator: uav_simulator.c $(CORE_SRC)
	$(CC) $(CFLAGS) -o uav_simulator$(EXT) uav_simulator.c $(CORE_SRC) $(LDFLAGS)

clean:
	rm -f *.o *.exe uavlink_benchmark gcs_receiver uav_simulator

.PHONY: all benchmark receiver simulator clean
