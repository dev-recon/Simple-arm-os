# Makefile principal pour tous les programmes userspace

PROGRAMS = ansy_tty hello malloc mash readfile term_dmo

BUILD_DIR = ../build
LIBC_DIR = ../libc

# Vérifier que libc est installée
.PHONY: all check-libc $(PROGRAMS) clean

all: check-libc $(PROGRAMS)

check-libc:
	echo "Building and installing libc..."; \
	$(MAKE) -C $(LIBC_DIR) distclean; \
	$(MAKE) -C $(LIBC_DIR) install; \


$(PROGRAMS):
	@echo "Building program: $@"
	$(MAKE) -C $@

clean:
	@for prog in $(PROGRAMS); do \
		echo "Cleaning $$prog..."; \
		$(MAKE) -C $$prog clean; \
	done

install: all
	@for prog in $(PROGRAMS); do \
		echo "Installing $$prog..."; \
		$(MAKE) -C $$prog install; \
	done
	