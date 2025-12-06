# Agent Guidelines for ddns-updater

## Build System

- Cross-platform Makefile supporting macOS (Darwin) and Linux
- macOS uses Homebrew paths for dependencies (curl, cunit)
- Linux enables security hardening linker flags (`-Wl,-z,relro,-z,now`)
- Strict compiler warnings with `-Werror` - all warnings are errors

## Compiler Warnings

This project uses aggressive warning flags. Pay attention to:

- `-Wformat-truncation` (GCC): Warns when `snprintf` output may be truncated. Fix by sizing buffers for worst-case static analysis, even if runtime constraints make truncation impossible.
- `-Wmissing-prototypes`: All non-static functions need prototypes in headers.
- `-Wsign-conversion`: Explicit casts required when converting between signed/unsigned.
- `-Wsometimes-uninitialized`: Variables must be initialized before any path that uses them (including after `goto`).

## Test Framework

- Uses CUnit for unit testing
- Test files live in `tests/`
- Each test file has a `test_*_register()` function declared in `tests/tests.h`
- Run tests with `make test`
- All test registration functions must be declared in `tests/tests.h` to satisfy `-Wmissing-prototypes`

## Code Style

- C11 standard (`-std=c11 -pedantic`)
- SPDX license identifiers in file headers
- Static functions for file-local helpers
- Buffer sizes should account for static analyzer limitations (e.g., `2 * DDNS_MAX_DOMAIN_LEN + 2` when concatenating two domain parts)

## Platform Considerations

- macOS: No RELRO support, uses Homebrew for dependencies
- Linux: Full security hardening, system packages for dependencies
- Both platforms must pass the same strict warning flags
