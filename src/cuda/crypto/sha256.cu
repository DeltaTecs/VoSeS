#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"
#include "../util.h"

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR((x), 2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define Sigma1(x) (ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define sigma0(x) (ROTR((x), 7) ^ ROTR((x), 18) ^ SHR((x), 3))
#define sigma1(x) (ROTR((x), 17) ^ ROTR((x), 19) ^ SHR((x), 10))

__constant__ static const uint32_t c_initial_hash[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

__constant__ static const uint32_t c_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ void process_block(const unsigned char* d_block, uint32_t* d_state) {
        uint32_t W[64];

        for (char t = 0; t < 16; ++t) {
            W[t] = ((uint32_t)d_block[t * 4] << 24) |
                   ((uint32_t)d_block[t * 4 + 1] << 16) |
                   ((uint32_t)d_block[t * 4 + 2] << 8) |
                   ((uint32_t)d_block[t * 4 + 3]);
        }

        for (char t = 16; t < 64; ++t) {
            W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
        }

        uint32_t a = d_state[0];
        uint32_t b = d_state[1];
        uint32_t c = d_state[2];
        uint32_t d = d_state[3];
        uint32_t e = d_state[4];
        uint32_t f = d_state[5];
        uint32_t g = d_state[6];
        uint32_t h_i = d_state[7];

        for (char t = 0; t < 64; ++t) {
            uint32_t T1 = h_i + Sigma1(e) + Ch(e, f, g) + c_K[t] + W[t];
            uint32_t T2 = Sigma0(a) + Maj(a, b, c);
            h_i = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        d_state[0] += a;
        d_state[1] += b;
        d_state[2] += c;
        d_state[3] += d;
        d_state[4] += e;
        d_state[5] += f;
        d_state[6] += g;
        d_state[7] += h_i;
}

__device__ void cuda_sha256(const unsigned char *d_input, short input_len, unsigned char *d_digest) {
    short original_byte_length = input_len;
    short total_required = original_byte_length + 1 + 8;
    short blocks_needed = (total_required + 63) / 64;
    short padded_length = blocks_needed * 64;

    uint64_t length_bits = (uint64_t)original_byte_length * 8;

    uint32_t h[8] = {c_initial_hash[0], c_initial_hash[1],
                     c_initial_hash[2], c_initial_hash[3],
                     c_initial_hash[4], c_initial_hash[5],
                     c_initial_hash[6], c_initial_hash[7]};

    // process main blocks
    int num_blocks = padded_length / 64;
    for (size_t i = 0; i < num_blocks - 1; ++i) {
        const unsigned char *block = d_input + i * 64;
        process_block(block, h);
    }

    // process last block (and possibly an extra block if needed)
    unsigned char last_msg_block[64];
    cuda_array_set_zero(last_msg_block, 64);

    // Compute the number of remaining bytes from the original message
    const int r = original_byte_length % 64;
    // Copy the remaining message bytes (if any) into the last block.
    // (If original_byte_length is a multiple of 64, r will be 0.)
    cuda_array_copy(last_msg_block, d_input + original_byte_length - r, r);
    // Append the mandatory 0x80 byte (which is the 1 bit followed by 7 zeros)
    last_msg_block[r] = 0x80;

    // Now, if there is room in this block for the 8-byte length (i.e. if r <= 55),
    // then we can finish this block; otherwise, we must process this block and create an extra block.
    if (r <= 55) {
        // Append length in bits in the final 8 bytes (big-endian)
        last_msg_block[56] = (length_bits >> 56) & 0xFF;
        last_msg_block[57] = (length_bits >> 48) & 0xFF;
        last_msg_block[58] = (length_bits >> 40) & 0xFF;
        last_msg_block[59] = (length_bits >> 32) & 0xFF;
        last_msg_block[60] = (length_bits >> 24) & 0xFF;
        last_msg_block[61] = (length_bits >> 16) & 0xFF;
        last_msg_block[62] = (length_bits >> 8)  & 0xFF;
        last_msg_block[63] = (length_bits)       & 0xFF;
        // Process this final block
        process_block(last_msg_block, h);
    } else {
        // When r > 55 the current block cannot hold the 64-bit length.
        // First process the block with the padding (without the length).
        process_block(last_msg_block, h);
        // Prepare a new block (all zeros) for the length.
        unsigned char extra_block[64] = {0};
        extra_block[56] = (length_bits >> 56) & 0xFF;
        extra_block[57] = (length_bits >> 48) & 0xFF;
        extra_block[58] = (length_bits >> 40) & 0xFF;
        extra_block[59] = (length_bits >> 32) & 0xFF;
        extra_block[60] = (length_bits >> 24) & 0xFF;
        extra_block[61] = (length_bits >> 16) & 0xFF;
        extra_block[62] = (length_bits >> 8)  & 0xFF;
        extra_block[63] = (length_bits)       & 0xFF;
        // Process the extra block that holds the length.
        process_block(extra_block, h);
    }

    #pragma unroll
    for (int i = 0; i < 8; ++i) {
        uint32_t hi = h[i];
        d_digest[i * 4 + 0] = (hi >> 24) & 0xFF;
        d_digest[i * 4 + 1] = (hi >> 16) & 0xFF;
        d_digest[i * 4 + 2] = (hi >> 8) & 0xFF;
        d_digest[i * 4 + 3] = hi & 0xFF;
    }
}