TARGETS := arpresponder trafficmonitor ndp_redirect

CC := gcc
LD := gcc
CFLAGS := -Os
LDFLAGS := $(CFLAGS)
STRIP := strip

all: $(TARGETS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

arpresponder: common.o arpresponder.o
	$(LD) $(LDFLAGS) -o $@ $^
	$(STRIP) $@

trafficmonitor: common.o trafficmonitor.o
	$(LD) $(LDFLAGS) -o $@ $^
	$(STRIP) $@

ndp_redirect: ndp_redirect.o
	$(LD) $(LDFLAGS) -o $@ $^
	$(STRIP) $@

clean:
	rm -f $(TARGETS) *.o
