
#include "sha384.h"
#include "../util.h"

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x, n) ((x) >> (n))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR((x), 28) ^ ROTR((x), 34) ^ ROTR((x), 39))
#define Sigma1(x) (ROTR((x), 14) ^ ROTR((x), 18) ^ ROTR((x), 41))
#define sigma0(x) (ROTR((x), 1) ^ ROTR((x), 8) ^ SHR((x), 7))
#define sigma1(x) (ROTR((x), 19) ^ ROTR((x), 61) ^ SHR((x), 6))

__constant__ static const uint64_t c_initial_hash[8] = {
    0xcbbb9d5dc1059ed8ULL,
    0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL,
    0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL,
    0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL,
    0x47b5481dbefa4fa4ULL
};

__constant__ static const uint64_t c_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

__device__ static inline void process_block(const uint8_t *block, uint64_t H[8]) {
    uint64_t W[80];
    #pragma unroll
    for (int t = 0; t < 16; t++) {
        W[t] = ((uint64_t)block[t*8] << 56) |
               ((uint64_t)block[t*8 + 1] << 48) |
               ((uint64_t)block[t*8 + 2] << 40) |
               ((uint64_t)block[t*8 + 3] << 32) |
               ((uint64_t)block[t*8 + 4] << 24) |
               ((uint64_t)block[t*8 + 5] << 16) |
               ((uint64_t)block[t*8 + 6] << 8) |
               ((uint64_t)block[t*8 + 7]);
    }
    #pragma unroll
    for (int t = 16; t < 80; t++) {
        W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
    }
    uint64_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint64_t e = H[4], f = H[5], g = H[6], h = H[7];
    #pragma unroll
    for (int t = 0; t < 80; t++) {
        uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + c_K[t] + W[t];
        uint64_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

__device__ void cuda_sha384(const unsigned char *d_input, size_t input_len, unsigned char *d_digest) {
    uint64_t H[8] = {c_initial_hash[0], c_initial_hash[1], c_initial_hash[2], c_initial_hash[3],
                     c_initial_hash[4], c_initial_hash[5], c_initial_hash[6], c_initial_hash[7]};

    size_t full_blocks = input_len / 128;
    for (size_t i = 0; i < full_blocks; i++) {
        process_block(d_input + i * 128, H);
    }

    uint8_t block[128];
    size_t remaining_bytes = input_len % 128;
    cuda_array_set_zero(block, sizeof(block));
    if (remaining_bytes > 0) {
        cuda_array_copy(block, d_input + full_blocks * 128, remaining_bytes);
    }
    block[remaining_bytes] = 0x80;

    if (remaining_bytes + 1 + 16 <= 128) {
        size_t zeros_needed = 112 - (remaining_bytes + 1);
        cuda_array_set_zero(block + remaining_bytes + 1, zeros_needed);
        uint64_t length_high = (input_len >> 61);
        uint64_t length_low = (input_len << 3);
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            block[112 + i] = (length_high >> (56 - i * 8)) & 0xFF;
            block[120 + i] = (length_low >> (56 - i * 8)) & 0xFF;
        }
        process_block(block, H);
    } else {
        cuda_array_set_zero(block + remaining_bytes + 1, 128 - remaining_bytes - 1);
        process_block(block, H);
        cuda_array_set_zero(block, 128);
        uint64_t length_high = (input_len >> 61);
        uint64_t length_low = (input_len << 3);
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            block[112 + i] = (length_high >> (56 - i * 8)) & 0xFF;
            block[120 + i] = (length_low >> (56 - i * 8)) & 0xFF;
        }
        process_block(block, H);
    }

    // copy result to output
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        uint64_t h_i = H[i];
        d_digest[i*8] = (h_i >> 56) & 0xFF;
        d_digest[i*8 + 1] = (h_i >> 48) & 0xFF;
        d_digest[i*8 + 2] = (h_i >> 40) & 0xFF;
        d_digest[i*8 + 3] = (h_i >> 32) & 0xFF;
        d_digest[i*8 + 4] = (h_i >> 24) & 0xFF;
        d_digest[i*8 + 5] = (h_i >> 16) & 0xFF;
        d_digest[i*8 + 6] = (h_i >> 8) & 0xFF;
        d_digest[i*8 + 7] = h_i & 0xFF;
    }
}