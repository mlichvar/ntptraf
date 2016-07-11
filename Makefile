CFLAGS = -g -O2 -Wall
LDFLAGS = -lpcap

all: ntptraf

clean:
	rm -f ntptraf
