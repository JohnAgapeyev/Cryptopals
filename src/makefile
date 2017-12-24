CC=gcc
BASEFLAGS=-Wall -Wextra -std=c11 -pedantic -D_POSIX_C_SOURCE=200809L -pipe
DEBUGFLAGS=-fsanitize=undefined -ggdb -O0
RELEASEFLAGS=-O3 -march=native -flto -DNDEBUG
CLIBS=-lcrypto

8count := 1 2 3 4 5 6 7 8

src_list = $(foreach dir, $(8count), $(wildcard set_$(dir)/*.c))
obj_list = $(foreach dir, $(8count), $(wildcard set_$(dir)/*.o))
elf_list = $(foreach dir, $(8count), $(wildcard set_$(dir)/*.elf))

all release debug: common.h common.o mersenne.h mersenne.o $(patsubst %.c, %.o, $(src_list)) $(patsubst %.c, %.elf, $(src_list))

%.o: %.c common.h mersenne.h
	$(CC) -c $(CFLAGS) $(patsubst %.o, %.c, $@) $(CLIBS) -o $@

%.elf: %.o common.o mersenne.o
	$(CC) $(CFLAGS) common.o mersenne.o $(patsubst %.elf, %.o, $@) $(CLIBS) -o $@

ifeq (,$(filter debug, $(MAKECMDGOALS)))
$(eval CFLAGS = $(BASEFLAGS) $(RELEASEFLAGS))
else
$(eval CFLAGS = $(BASEFLAGS) $(DEBUGFLAGS))
endif

.PHONY: clean
clean:
	$(RM) common.o $(obj_list) $(elf_list)
	@$(RM) $(wildcard *.gch)

