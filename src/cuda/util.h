
#include <stdio.h>
#include <stdint.h>

// ignore cuda symbol errors, visual studio is not able to follo wthe include path for whatever reason

__host__ static inline void array_copy(unsigned char* dst, const unsigned char* src, int length) {
    #pragma unroll
    for (int i = 0; i < length; i++) {
        dst[i] = src[i];
    }
}

__host__ static inline void array_set_zero(unsigned char* dst, int length) {
    #pragma unroll
    for (int i = 0; i < length; i++) {
        dst[i] = 0x00;
    }
}

__device__ static inline void cuda_array_copy(unsigned char* d_dst, const unsigned char* d_src, int length) {
    #pragma unroll
    for (int i = 0; i < length; i++) {
        d_dst[i] = d_src[i];
    }
}

__device__ static inline void cuda_array_set_zero(unsigned char* d_dst, int length) {
    #pragma unroll
    for (int i = 0; i < length; i++) {
        d_dst[i] = 0x00;
    }
}