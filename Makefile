CC = gcc
CFLAGS = -O3 -Wall `pkg-config --cflags libsodium`
LDLIBS = `pkg-config --libs libsodium`

PROGRAM = crypt_rclone.exe
OBJS = crypt_rclone.o

all:	$(PROGRAM)

$(PROGRAM):	$(OBJS)
	$(CC) $(LDFLAGS) $(TARGET_ARCH) $^ $(LOADLIBES) $(LDLIBS) -o $@

.PHONY: clean
clean:
	$(RM) $(PROGRAM) $(OBJS)
