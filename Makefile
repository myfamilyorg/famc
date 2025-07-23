CC = clang
CFLAGS = -O3
SRCDIR = src
OBJDIR = .obj
C_SOURCES = $(filter-out $(SRCDIR)/test.c, $(wildcard $(SRCDIR)/*.c))
OBJECTS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(C_SOURCES))

.PHONY: all clean

all: bin/famc

bin/famc: $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ -lfam

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -DSTATIC=static -c $< -o $@ -I/usr/include/libfam -Iinclude

clean:
	rm -f $(OBJDIR)/*.o bin/famc
