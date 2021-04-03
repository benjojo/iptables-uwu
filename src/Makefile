CFLAGS += -Wall -O2 $(shell pkg-config --cflags xtables) -fPIC
LDFLAGS += $(shell pkg-config --libs xtables)
XTLIBDIR := $(shell pkg-config --variable xtlibdir xtables)
KDIR ?=  /lib/modules/`uname -r`/build

XTABLES_MODULES := $(patsubst %.c,%.so,$(wildcard libxt_*.c))

.PHONY: all install

all: ${XTABLES_MODULES}
	$(MAKE) -C ${KDIR} M=$(shell pwd) modules

lib%.so: lib%.o
	$(CC) -o $@ -shared $< ${LDFLAGS}

%.o: %.c
	$(CC) -o $@ -c $< ${CFLAGS}

install: all
	$(MAKE) -C ${KDIR} M=$(shell pwd) modules_install
	install -d ${XTLIBDIR}
	install ${XTABLES_MODULES} ${XTLIBDIR}

clean:
	$(MAKE) -C ${KDIR} M=$(shell pwd) clean
	$(RM) *.o *.so
