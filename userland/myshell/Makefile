# Makefile pour MyShell

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu89 -pedantic -g -O2
CPPFLAGS = -Iinclude
LDFLAGS = 
LIBS = 

# Repertoires
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin

# Fichiers source
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/myshell

# Regle par defaut
all: $(TARGET)

# Creation des repertoires
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# Compilation de l'executable
$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

# Compilation des fichiers objets
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Nettoyage
clean:
	rm -rf $(OBJDIR) $(BINDIR)

# Nettoyage complet
distclean: clean
	rm -f .myshell_history

# Installation
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod 755 /usr/local/bin/myshell

# Desinstallation
uninstall:
	rm -f /usr/local/bin/myshell

# Tests
test: $(TARGET)
	@echo "Tests basiques de MyShell"
	@echo "=========================="
	@echo "echo 'Hello World'" | $(TARGET)
	@echo "pwd" | $(TARGET)
	@echo "export TEST=hello && echo \$$TEST" | $(TARGET)

# Debug avec gdb
debug: $(TARGET)
	gdb $(TARGET)

# Debug avec valgrind
valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all $(TARGET)

# Generation de la documentation
doc:
	@echo "Generation de la documentation..."
	doxygen Doxyfile 2>/dev/null || echo "Doxygen non installe"

# Verification du style de code
style:
	@echo "Verification du style de code..."
	@for file in $(SOURCES) $(wildcard $(INCDIR)/*.h); do \
		echo "Checking $$file..."; \
		indent -gnu -i4 -ts4 -sob -l80 -ss -ncs -cp1 < "$$file" | \
		diff -u "$$file" - || true; \
	done

# Analyse statique
analyze:
	@echo "Analyse statique avec cppcheck..."
	cppcheck --enable=all --std=c89 --platform=unix64 \
		--suppress=missingIncludeSystem $(SRCDIR)/ 2>/dev/null || \
		echo "cppcheck non installe"

# Creation d'un fichier RC d'exemple
example-rc:
	@echo "# Fichier de configuration MyShell" > .myshellrc.example
	@echo "# Copier vers ~/.myshellrc pour l'utiliser" >> .myshellrc.example
	@echo "" >> .myshellrc.example
	@echo "# Prompt personnalise" >> .myshellrc.example
	@echo "export PS1='[\u@\h \W]\$ '" >> .myshellrc.example
	@echo "" >> .myshellrc.example
	@echo "# Alias utiles" >> .myshellrc.example
	@echo "# (Note: MyShell ne supporte pas encore les alias)" >> .myshellrc.example
	@echo "" >> .myshellrc.example
	@echo "# Variables d'environnement" >> .myshellrc.example
	@echo "export EDITOR=nano" >> .myshellrc.example
	@echo "export PAGER=less" >> .myshellrc.example
	@echo "" >> .myshellrc.example
	@echo "# Afficher un message de bienvenue" >> .myshellrc.example
	@echo "echo 'Bienvenue dans MyShell!'" >> .myshellrc.example

# Aide
help:
	@echo "Makefile pour MyShell"
	@echo "====================="
	@echo ""
	@echo "Cibles disponibles:"
	@echo "  all        - Compiler MyShell (defaut)"
	@echo "  clean      - Nettoyer les fichiers generes"
	@echo "  distclean  - Nettoyage complet"
	@echo "  install    - Installer MyShell dans /usr/local/bin"
	@echo "  uninstall  - Desinstaller MyShell"
	@echo "  test       - Executer des tests basiques"
	@echo "  debug      - Lancer avec gdb"
	@echo "  valgrind   - Verifier les fuites memoire"
	@echo "  doc        - Generer la documentation"
	@echo "  style      - Verifier le style de code"
	@echo "  analyze    - Analyse statique du code"
	@echo "  example-rc - Creer un fichier RC d'exemple"
	@echo "  help       - Afficher cette aide"

# Dependances
$(OBJDIR)/main.o: $(INCDIR)/shell.h
$(OBJDIR)/parser.o: $(INCDIR)/shell.h
$(OBJDIR)/executor.o: $(INCDIR)/shell.h
$(OBJDIR)/builtins.o: $(INCDIR)/shell.h
$(OBJDIR)/variables.o: $(INCDIR)/shell.h
$(OBJDIR)/history.o: $(INCDIR)/shell.h
$(OBJDIR)/jobs.o: $(INCDIR)/shell.h
$(OBJDIR)/signals.o: $(INCDIR)/shell.h
$(OBJDIR)/rcfiles.o: $(INCDIR)/shell.h
$(OBJDIR)/prompt.o: $(INCDIR)/shell.h

.PHONY: all clean distclean install uninstall test debug valgrind doc style analyze example-rc help