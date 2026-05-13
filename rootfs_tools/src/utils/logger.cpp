#include "logger.hpp"
#include <cstdio>
#include <cstdarg>
#include <ctime>

#ifdef _WIN32
#  include <io.h>
#  define isatty   _isatty
#  define fileno   _fileno
#else
#  include <unistd.h>
#endif

namespace {

bool g_debug = false;

// ANSI escape codes
static const char *COL_RESET   = "\033[0m";
static const char *COL_BOLD_RED= "\033[0;31m";
static const char *COL_GREEN   = "\033[0;32m";
static const char *COL_YELLOW  = "\033[0;33m";
static const char *COL_DIM     = "\033[2m";
static const char *COL_BOLD    = "\033[1m";

inline bool color_stdout() { return isatty(fileno(stdout))  != 0; }
inline bool color_stderr() { return isatty(fileno(stderr)) != 0; }

void format_timestamp(char *out, size_t out_size) {
    std::time_t now = std::time(nullptr);
    std::tm tm_now{};
#ifdef _WIN32
    localtime_s(&tm_now, &now);
#else
    localtime_r(&now, &tm_now);
#endif
    std::strftime(out, out_size, "%Y-%m-%d %H:%M:%S", &tm_now);
}

void vprint(FILE *stream, const char *level, const char *pre, const char *post,
            bool use_col, const char *fmt, va_list ap) {
    char ts[20] = {0};
    format_timestamp(ts, sizeof(ts));

    std::fprintf(stream, "[%s] ", ts);
    if (level && *level) {
        if (use_col && pre)  fputs(pre, stream);
        fputc('[', stream);
        fputs(level, stream);
        fputs("] ", stream);
        if (use_col && post) fputs(post, stream);
    }
    vfprintf(stream, fmt, ap);
    fputc('\n', stream);
}

} // namespace

void Log::set_debug(bool enabled) { g_debug = enabled; }
bool Log::is_debug()              { return g_debug; }

void Log::info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vprint(stdout, "INFO", COL_GREEN, COL_RESET, color_stdout(), fmt, ap);
    va_end(ap);
}

void Log::warn(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vprint(stdout, "WARN", COL_YELLOW, COL_RESET, color_stdout(), fmt, ap);
    va_end(ap);
}

void Log::error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vprint(stderr, "ERROR", COL_BOLD_RED, COL_RESET, color_stderr(), fmt, ap);
    va_end(ap);
}

void Log::debug(const char *fmt, ...) {
    if (!g_debug) return;
    va_list ap; va_start(ap, fmt);
    vprint(stdout, "DEBUG", COL_DIM, COL_RESET, color_stdout(), fmt, ap);
    va_end(ap);
}

void Log::hexdump(const char *label, const uint8_t *buf, int size) {
    bool col = color_stdout();
    if (label && *label) {
        if (col) fputs(COL_BOLD, stdout);
        printf("%s:", label);
        if (col) fputs(COL_RESET, stdout);
        putchar('\n');
    }
    if (col) fputs(COL_DIM, stdout);
    for (int i = 0; i < size; i += 16) {
        printf("%08X: ", i);
        for (int j = 0; j < 16; j++) {
            if (i + j < size) printf("%02X ", buf[i + j]);
            else               printf("   ");
        }
        printf(" ");
        for (int j = 0; j < 16; j++) {
            if (i + j < size) {
                uint8_t c = buf[i + j];
                printf("%c", (c >= ' ' && c < 127) ? c : '.');
            }
        }
        putchar('\n');
    }
    if (col) fputs(COL_RESET, stdout);
}
