# Makefile principal pour tous les programmes userspace

PROGRAMS = ansy_tty coreutils hello malloc mash readfile systest term_dmo
NEWLIB_PROGRAMS = newlib-tests
BUILD_NEWLIB ?= 0

BUILD_DIR = ../build
LIBC_DIR = ../libc

# Vérifier que libc est installée
.PHONY: all check-libc $(PROGRAMS) $(NEWLIB_PROGRAMS) clean install-newlib

all: check-libc $(PROGRAMS)

ifeq ($(BUILD_NEWLIB),1)
all: $(NEWLIB_PROGRAMS)
endif

check-libc:
	echo "Building and installing libc..."; \
	$(MAKE) -C $(LIBC_DIR) clean; \
	$(MAKE) -C $(LIBC_DIR) install; \


$(PROGRAMS):
	@echo "Building program: $@"
	$(MAKE) -C $@

$(NEWLIB_PROGRAMS):
	@echo "Building newlib program: $@"
	$(MAKE) -C $@ NEWLIB_SYSROOT="$(NEWLIB_SYSROOT)"

clean:
	@for prog in $(PROGRAMS); do \
		echo "Cleaning $$prog..."; \
		$(MAKE) -C $$prog clean; \
	done
	@for prog in $(NEWLIB_PROGRAMS); do \
		if [ -d "$$prog" ]; then \
			echo "Cleaning $$prog..."; \
			$(MAKE) -C $$prog clean; \
		fi; \
	done

install: all
	@for prog in $(PROGRAMS); do \
		echo "Installing $$prog..."; \
		$(MAKE) -C $$prog install; \
	done
	@if [ "$(BUILD_NEWLIB)" = "1" ]; then \
		for prog in $(NEWLIB_PROGRAMS); do \
			echo "Installing $$prog..."; \
			$(MAKE) -C $$prog install; \
		done; \
	fi

install-newlib:
	$(MAKE) -C newlib-tests install
	
