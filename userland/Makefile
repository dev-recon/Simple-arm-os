# Main userland Makefile.
#
# Newlib is the supported ArmOS userspace ABI. Legacy home-grown libc
# programs are kept under userland/legacy for reference only.

NEWLIB_PROGRAMS = newlib-tests
BUILD_NEWLIB ?= 0
ARCH ?= arm-none-eabi-
NEWLIB_SYSROOT ?= ../build/newlib-sysroot/arm-none-eabi
NEWLIB_LIBC ?= $(NEWLIB_SYSROOT)/lib/libc.a

all: $(NEWLIB_PROGRAMS)

$(NEWLIB_PROGRAMS):
	@echo "Building userland: $@"
	$(MAKE) -C $@ ARCH="$(ARCH)" NEWLIB_SYSROOT="$(NEWLIB_SYSROOT)" NEWLIB_LIBC="$(NEWLIB_LIBC)"

clean:
	@for prog in $(NEWLIB_PROGRAMS); do \
		if [ -d "$$prog" ]; then \
			echo "Cleaning $$prog..."; \
			$(MAKE) -C $$prog clean; \
		fi; \
	done

install: all
	@for prog in $(NEWLIB_PROGRAMS); do \
		echo "Installing $$prog..."; \
		$(MAKE) -C $$prog install ARCH="$(ARCH)" NEWLIB_SYSROOT="$(NEWLIB_SYSROOT)" NEWLIB_LIBC="$(NEWLIB_LIBC)"; \
	done

install-newlib:
	$(MAKE) -C newlib-tests install ARCH="$(ARCH)" NEWLIB_SYSROOT="$(NEWLIB_SYSROOT)" NEWLIB_LIBC="$(NEWLIB_LIBC)"
	
