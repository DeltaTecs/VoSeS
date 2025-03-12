
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

// Multiply two 128-bit numbers X and Y in GF(2^128) using the
// polynomial x^128 + x^7 + x^2 + x + 1. The result is written into result.
__device__ static inline void cuda_multiply_gf128(const uint8_t *X, const uint8_t *Y, uint8_t *result) {
    uint8_t Z[16] = {0};  // Accumulator for the result, initially 0
    uint8_t V[16];
    cuda_array_copy(V, X, 16);

    // Process each of the 128 bits of Y, starting with the most-significant bit.
    for (int i = 0; i < 128; i++) {
        // Check the i-th bit of Y. Bits are processed from left (MSB) to right (LSB).
        if ((Y[i >> 3] >> (7 - (i & 7))) & 1) {
            // If the bit is 1, XOR V into Z.
            for (int j = 0; j < 16; j++) {
                Z[j] ^= V[j];
            }
        }
        // Save the least significant bit of V (the bit that will be shifted out)
        int lsb = V[15] & 1;
        // Shift V right by 1 bit.
        // This loop shifts each byte, carrying the LSB of the previous byte into the next.
        for (int j = 15; j > 0; j--) {
            V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
        }
        V[0] >>= 1;
        // If the bit shifted out was 1, reduce V modulo the polynomial by XORing 0xe1
        if (lsb)
            V[0] ^= 0xe1;
    }
    // Write the resulting 128-bit value to the output.
    cuda_array_copy(result, Z, 16);
}