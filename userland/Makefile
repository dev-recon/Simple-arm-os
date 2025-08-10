# Makefile principal pour tous les programmes userspace

PROGRAMS = hello shell calculator

BUILD_DIR = ../build
LIBC_DIR = ../libc

# Vérifier que libc est installée
.PHONY: all check-libc $(PROGRAMS) clean

all: check-libc $(PROGRAMS)

check-libc:
	@if [ ! -f "$(BUILD_DIR)/lib/libc.a" ]; then \
		echo "Building and installing libc..."; \
		$(MAKE) -C $(LIBC_DIR) install; \
	fi

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
	