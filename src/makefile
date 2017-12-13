CC=gcc
BASEFLAGS=-Wall -Wextra -std=c11 -pedantic -D_POSIX_C_SOURCE=200809L -pipe
DEBUGFLAGS=-fsanitize=undefined -fsanitize=address -ggdb -O0
RELEASEFLAGS=-O3 -march=native -flto -DNDEBUG
CLIBS=-lcrypto
BASEFLAGS=-Wall -Wextra -std=c11 -pedantic -D_POSIX_C_SOURCE=200809L

8count := 1 2 3 4 5 6 7 8

all release debug: common.h $(patsubst set%.c, bin/set%.elf, $(foreach dir, $(8count), $(wildcard set_$(dir)/*))) | dir

bin/%.elf: common.h
	$(CC) $(CFLAGS) common.c $(patsubst bin/%.elf, %.c, $@) $(CLIBS) -o $(subst .c, .elf, $@)

.PHONY: dir
dir:
	@mkdir -p bin
	@for set in 1 2 3 4 ; do \
		mkdir -p bin/set_$$set ; \
	done

ifeq (,$(filter debug, $(MAKECMDGOALS)))
$(eval CFLAGS = $(BASEFLAGS) $(RELEASEFLAGS))
else
$(eval CFLAGS = $(BASEFLAGS) $(DEBUGFLAGS))
endif

.PHONY: clean
clean: | $(ODIR)
	$(RM) $(foreach dir, $(8count), $(wildcard bin/set_$(dir)/*))
	@$(RM) $(wildcard *.gch)

