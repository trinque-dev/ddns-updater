# Makefile for ddns-updater
#
# SPDX-License-Identifier: MIT

# Compiler and flags
CC ?= cc
CFLAGS ?= -O2
CFLAGS += -std=c11 -pedantic
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -Wformat=2 -Wformat-security
CFLAGS += -Wconversion -Wsign-conversion
CFLAGS += -Wshadow -Wpointer-arith
CFLAGS += -Wcast-qual -Wcast-align
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -Wredundant-decls
CFLAGS += -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -I$(SRCDIR)/../include

# Platform-specific adjustments
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS: no RELRO support, use Homebrew curl/cunit if available
    LDFLAGS ?=
    CURL_PREFIX := $(shell brew --prefix curl 2>/dev/null)
    ifneq ($(CURL_PREFIX),)
        CFLAGS += -I$(CURL_PREFIX)/include
        LDFLAGS += -L$(CURL_PREFIX)/lib
    endif
    CUNIT_PREFIX := $(shell brew --prefix cunit 2>/dev/null)
    ifneq ($(CUNIT_PREFIX),)
        CFLAGS += -I$(CUNIT_PREFIX)/include
        LDFLAGS += -L$(CUNIT_PREFIX)/lib
    endif
else
    # Linux: enable security hardening linker flags
    LDFLAGS ?=
    LDFLAGS += -Wl,-z,relro,-z,now
endif

# Libraries
LDLIBS = -lcurl

# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin
TESTDIR = tests

# Source files (excluding main.c for test builds)
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

# Library objects (everything except main.o, for linking with tests)
LIB_OBJS = $(filter-out $(OBJDIR)/main.o,$(OBJS))

# Test files
TEST_SRCS = $(wildcard $(TESTDIR)/*.c)
TEST_OBJS = $(patsubst $(TESTDIR)/%.c,$(OBJDIR)/test_%.o,$(TEST_SRCS))

# Targets
TARGET = $(BINDIR)/ddns-updater
TEST_TARGET = $(BINDIR)/test-runner

# Default target
.PHONY: all
all: $(TARGET)

# Create directories
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Link
$(TARGET): $(OBJS) | $(BINDIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

# Compile test files
$(OBJDIR)/test_%.o: $(TESTDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(TESTDIR) -c -o $@ $<

# Link test runner
$(TEST_TARGET): $(LIB_OBJS) $(TEST_OBJS) | $(BINDIR)
	$(CC) $(LDFLAGS) -o $@ $(LIB_OBJS) $(TEST_OBJS) $(LDLIBS) -lcunit

# Build and run tests
.PHONY: test
test: $(TEST_TARGET)
	@echo "Running tests..."
	@./$(TEST_TARGET)

# Build tests only
.PHONY: build-tests
build-tests: $(TEST_TARGET)

# Debug build
.PHONY: debug
debug: CFLAGS += -g -O0 -DDEBUG
debug: CFLAGS := $(filter-out -O2,$(CFLAGS))
debug: clean $(TARGET)

# Address sanitizer build
.PHONY: asan
asan: CFLAGS += -g -O1 -fsanitize=address -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address
asan: clean $(TARGET)

# Undefined behavior sanitizer build
.PHONY: ubsan
ubsan: CFLAGS += -g -O1 -fsanitize=undefined
ubsan: LDFLAGS += -fsanitize=undefined
ubsan: clean $(TARGET)

# Static analysis
.PHONY: analyze
analyze:
	@echo "Running static analysis..."
	@if command -v scan-build >/dev/null 2>&1; then \
		scan-build --status-bugs $(MAKE) clean all; \
	elif command -v clang --analyze >/dev/null 2>&1; then \
		for src in $(SRCS); do \
			echo "Analyzing $$src"; \
			clang --analyze $(CFLAGS) $$src; \
		done; \
	else \
		echo "No static analyzer found (install clang or scan-build)"; \
		exit 1; \
	fi

# Format check
.PHONY: format-check
format-check:
	@echo "Checking code formatting..."
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format --dry-run --Werror $(SRCS) include/*.h; \
	else \
		echo "clang-format not found, skipping"; \
	fi

# Install
PREFIX ?= /usr/local
.PHONY: install
install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/

# Uninstall
.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/ddns-updater

# Clean
.PHONY: clean
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	rm -f *.plist  # clang static analyzer output

# Clean and rebuild tests
.PHONY: clean-tests
clean-tests:
	rm -f $(TEST_OBJS) $(TEST_TARGET)

# Help
.PHONY: help
help:
	@echo "ddns-updater Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build the project (default)"
	@echo "  test         Build and run tests"
	@echo "  build-tests  Build tests without running"
	@echo "  debug        Build with debug symbols"
	@echo "  asan         Build with AddressSanitizer"
	@echo "  ubsan        Build with UndefinedBehaviorSanitizer"
	@echo "  analyze      Run static analysis"
	@echo "  format-check Check code formatting"
	@echo "  install      Install to PREFIX (default: /usr/local)"
	@echo "  uninstall    Remove installed files"
	@echo "  clean        Remove build artifacts"
	@echo "  clean-tests  Remove test artifacts only"
	@echo "  help         Show this message"
	@echo ""
	@echo "Variables:"
	@echo "  CC           C compiler (default: cc)"
	@echo "  CFLAGS       Additional compiler flags"
	@echo "  LDFLAGS      Additional linker flags"
	@echo "  PREFIX       Installation prefix (default: /usr/local)"
	@echo "  DESTDIR      Staging directory for install"
