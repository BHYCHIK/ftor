.PHONY: all install

SUBDIRS = src
CFLAGS = -Werror -Wall -Wextra -pedantic
export CFLAGS

all:build_sources

debug: CFLAGS += -g
debug: all

clean:
	for sdir in $(SUBDIRS); do \
		$(MAKE) -C $$sdir clean ; \
	done

build_sources:
	export CFLAGS
	for sdir in $(SUBDIRS); do \
		$(MAKE) -C $$sdir -e build_sources ;\
	done
