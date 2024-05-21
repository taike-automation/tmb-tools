DESTDIR ?= /usr/local
TOOLS = tmbdump tmbexec tmbtest

.PHONY: clean all install

all: $(TOOLS)

$(TOOLS): %: %.c
	$(CC) -o '$@' '$<' -lpthread

clean:
	rm -f $(TOOLS)

install: $(TOOLS)
	mkdir -p $(DESTDIR)/sbin
	install -m 0755 -t $(DESTDIR)/sbin $^
