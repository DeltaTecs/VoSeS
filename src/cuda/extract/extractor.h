
#include <cstdint>
#include <cuda_runtime.h>

__host__ unsigned long long entropy_scan(const unsigned char* haystack, const uint64_t haystack_length, const uint64_t needle_length, const float entropyThreshold);
