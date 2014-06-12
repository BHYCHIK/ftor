.PHONY: all install

SUBDIRS = src
CFLAGS = -Werror -Wall -Wextra -pedantic --std=gnu99 -O3 -fno-strict-aliasing
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

install:
	mkdir -p /etc/ftor;
	@if [ -f /etc/ftor/ftor.conf ];\
	then\
		echo "Config exists.";\
	else\
		echo "Config does not exist. Coping example.";\
		cp ./ftor.conf.example /etc/ftor/ftor.conf;\
	fi
	@if [ -f /etc/ftor/private_key.example ];\
	then \
		echo "Example of private key exists.";\
	else\
		echo "Example of private key does not exist. Coping example.";\
		cp ./private_key.example /etc/ftor/private_key.example;\
	fi

