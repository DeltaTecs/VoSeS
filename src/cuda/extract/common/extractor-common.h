#pragma once

#include <cstdint>
#include <cuda_runtime.h>
#include <math.h>

constexpr unsigned long long k_addr_not_found = ~0ULL;

#ifdef __CUDACC__
extern __device__ __constant__ uint64_t d_memory_alignment;

__device__ inline float calculateEntropy(const unsigned char* data, int len) {
    float hist[256] = {0.0f};

    for (int i = 0; i < len; ++i) {
        hist[data[i]] += 1.0f;
    }

    float entropy = 0.0f;
    for (int i = 0; i < 256; ++i) {
        if (hist[i] > 0.0f) {
            float p = hist[i] / len;
            entropy -= p * log2f(p);
        }
    }
    return entropy;
}
#endif

__host__ bool set_memory_alignment(uint64_t alignment);
__host__ uint64_t get_memory_alignment();
__host__ unsigned long long entropy_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                         const uint64_t needle_length, const float entropyThreshold);

void print_tls13_app_traffic_secret_0(const unsigned char* secret, int secret_len,
                                      const unsigned char client_random[32], bool client,
                                      unsigned long long location);
