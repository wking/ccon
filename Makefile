CC := gcc
CFLAGS := $(shell pkg-config --cflags jansson libcap-ng) -Wall
LDFLAGS := $(shell pkg-config --libs-only-L jansson libcap-ng) -Wall
LDLIBS := $(shell pkg-config --libs-only-l jansson libcap-ng)

.PHONY: all clean fmt
.PRECIOUS: %.o

all: ccon ccon-cli

%.o: %.c
	$(CC) $(CFLAGS) -c -o "$@" "$<"

ccon ccon-cli: %: %.o libccon.o
	$(CC) $(LDFLAGS) -o "$@" $^ $(LDLIBS)

clean:
	rm -f *.o ccon ccon-cli

fmt:
	indent --ignore-profile --linux-style *.h *.c
