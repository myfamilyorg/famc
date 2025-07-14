CC=clang
CFLAGS=-O3
SRCDIR=src
C_SOURCES   = $(filter-out $(SRCDIR)/test.c,$(wildcard $(SRCDIR)/*.c))
INCLUDE=/usr/include/libfam

all:
	$(CC) $(CFLAGS) -o bin/famc -lfam -I$(INCLUDE) $(C_SOURCES)
