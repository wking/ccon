CC := cc
CFLAGS := $(shell pkg-config --cflags jansson libcap-ng)
LDFLAGS := $(shell pkg-config --libs-only-L jansson libcap-ng)
LDLIBS := $(shell pkg-config --libs-only-l jansson libcap-ng)

.PHONY: all clean fmt
.PRECIOUS: %.o

all: ccon

%.o: %.c
	$(CC) $(CFLAGS) -c -o "$@" "$<"

ccon: %: %.o
	$(CC) $(LDFLAGS) -o "$@" "$<" $(LDLIBS) 

clean:
	rm -f *.o ccon

fmt:
	indent --ignore-profile --linux-style *.c
