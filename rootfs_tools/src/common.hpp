#pragma once
#include <cstdint>
#include <cstddef>

#if defined(_WIN32) || defined(_WIN64)
#  define SIZE_T_FMT "%Iu"
#else
#  define SIZE_T_FMT "%zu"
#endif

