#pragma once
#include <cstdint>

#ifdef __GNUC__
#  define LOG_PRINTF_ATTR(a, b) __attribute__((format(printf, a, b)))
#else
#  define LOG_PRINTF_ATTR(a, b)
#endif

namespace Log {

void set_debug(bool enabled);
bool is_debug();

// All functions automatically append a newline.
// Pass format string WITHOUT a trailing '\n'.

void info   (const char *fmt, ...) LOG_PRINTF_ATTR(1, 2);   // default color
void success(const char *fmt, ...) LOG_PRINTF_ATTR(1, 2);   // bold green
void warn   (const char *fmt, ...) LOG_PRINTF_ATTR(1, 2);   // yellow
void error  (const char *fmt, ...) LOG_PRINTF_ATTR(1, 2);   // bold red  -> stderr
void debug  (const char *fmt, ...) LOG_PRINTF_ATTR(1, 2);   // dim       (no-op when debug off)

// Always prints (caller must guard with Log::is_debug() if wanted).
void hexdump(const char *label, const uint8_t *buf, int size);

} // namespace Log
