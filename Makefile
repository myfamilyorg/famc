# Compiler and tools
CC = gcc

# Directories
SRCDIR = src
INCLDIR = src/include
LIBDIR = lib
BINDIR = bin
OBJDIR = .obj
TEST_OBJDIR = .testobj
TOBJDIR = .tobj
SRC_DIRS = lexer main

# Installation paths
PREFIX ?= /usr
INSTALL_LIBDIR = $(PREFIX)/lib64
INCDIR = $(PREFIX)/include
INSTALL = install
INSTALL_BIN = $(INSTALL) -m 755
INSTALL_DATA = $(INSTALL) -m 644
INSTALL_DIR = $(INSTALL) -d

# Source and object files (exclude main.c from tests to avoid _start/main conflicts)
C_SOURCES = $(foreach dir,$(SRC_DIRS), \
		$(filter-out $(SRCDIR)/$(dir)/test.c $(SRCDIR)/main/main.c, \
		$(wildcard $(SRCDIR)/$(dir)/*.c)))
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(C_SOURCES)) \
	  $(OBJDIR)/main/main.o  # Include main.c for main binary
TEST_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(TEST_OBJDIR)/%.o,$(C_SOURCES))

# Test sources and objects
TEST_SRC = $(foreach dir,$(SRC_DIRS),$(SRCDIR)/$(dir)/test.c)
TEST_OBJ = $(patsubst $(SRCDIR)/%.c,$(TOBJDIR)/%.o,$(TEST_SRC))
TEST_BIN = $(BINDIR)/runtests

# Binary name
BINARY = $(BINDIR)/famc

# Common configuration
PAGE_SIZE = 16384
MEMSAN ?= 0
FILTER ?= "*"

# Common flags
COMMON_FLAGS = -Wall \
			   -Wextra \
			   -std=c89 \
			   -Werror \
			   -I$(INCLDIR) \
			   -DMEMSAN=$(MEMSAN) \
			   -fno-builtin \
		   -Wno-pointer-sign \
			   -Wno-incompatible-library-redeclaration

# Arch-specific flags
ARCH_FLAGS_x86_64 = -msse4.2
ARCH_FLAGS_aarch64 = -march=armv8-a+crc

# Detect architecture (default to x86_64)
ARCH = $(shell uname -m)
ifeq ($(ARCH),x86_64)
	ARCH_FLAGS = $(ARCH_FLAGS_x86_64)
else
	ARCH_FLAGS = $(ARCH_FLAGS_aarch64)
endif

# Specific flags
BIN_CFLAGS = $(COMMON_FLAGS) $(ARCH_FLAGS) -O3 -DSTATIC=static
TEST_CFLAGS = $(COMMON_FLAGS) $(ARCH_FLAGS) -O1 -DSTATIC= -DTEST=1
TEST_BINARY_CFLAGS = $(COMMON_FLAGS) $(ARCH_FLAGS) -ffreestanding -nostdlib -O1 -DSTATIC= -DTEST=1
LDFLAGS = -O3 -ffreestanding -nostdlib

# Default target
all: $(BINARY)

# Create directories
$(OBJDIR) $(TEST_OBJDIR) $(TOBJDIR) $(BINDIR):
	@mkdir -p $@

# Rules for main binary objects
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	@mkdir -p $(@D)
	$(CC) $(BIN_CFLAGS) -c $< -o $@

# Build main binary
$(BINARY): $(OBJECTS) | $(BINDIR)
	$(CC) $(BIN_CFLAGS) $(LDFLAGS) -o $@ $^ -lfam

# Rules for test objects from main sources (using TEST_CFLAGS)
$(TEST_OBJDIR)/%.o: $(SRCDIR)/%.c | $(TEST_OBJDIR)
	@mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

# Rules for test objects
$(TOBJDIR)/%.o: $(SRCDIR)/%.c | $(TOBJDIR)
	@mkdir -p $(@D)
	$(CC) $(TEST_BINARY_CFLAGS) -c $< -o $@

# Build test binary (depends on TEST_OBJECTS and TEST_OBJ, excludes main.c)
$(TEST_BIN): $(TEST_OBJECTS) $(TEST_OBJ) | $(BINDIR)
	$(CC) $(TEST_BINARY_CFLAGS) $(LDFLAGS) $(SRCDIR)/test/main.c -o $@ $(TEST_OBJECTS) $(TEST_OBJ) -lfam

# Run tests
test: $(TEST_BIN)
	export TEST_PATTERN=$(FILTER); $(TEST_BIN)

# Clean up
clean:
	rm -rf $(OBJDIR) $(TEST_OBJDIR) $(TOBJDIR) $(BINDIR)/*

# Install rule (for binary)
install: $(BINARY)
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	$(INSTALL_BIN) $(BINARY) $(DESTDIR)$(BINDIR)/famc

# Uninstall rule
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/famc

# Phony targets
.PHONY: all test clean install uninstall
