
#include "sha384.h"

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x, n) ((x) >> (n))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR((x), 28) ^ ROTR((x), 34) ^ ROTR((x), 39))
#define Sigma1(x) (ROTR((x), 14) ^ ROTR((x), 18) ^ ROTR((x), 41))
#define sigma0(x) (ROTR((x), 1) ^ ROTR((x), 8) ^ SHR((x), 7))
#define sigma1(x) (ROTR((x), 19) ^ ROTR((x), 61) ^ SHR((x), 6))

static const uint64_t initial_hash[8] = {
    0xcbbb9d5dc1059ed8ULL,
    0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL,
    0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL,
    0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL,
    0x47b5481dbefa4fa4ULL
};

static const uint64_t K[80] = {
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

void sha384(const unsigned char *input, size_t input_len, unsigned char *digest) {
    size_t original_byte_length = input_len;
    size_t total_required = original_byte_length + 1 + 16;
    size_t blocks_needed = (total_required + 127) / 128;
    size_t padded_length = blocks_needed * 128;
    size_t k = padded_length - original_byte_length - 1 - 16;

    unsigned char *padded_msg = (unsigned char *)malloc(padded_length);
    if (!padded_msg) {
        perror("malloc failed");
        exit(1);
    }

    memcpy(padded_msg, input, original_byte_length);
    padded_msg[original_byte_length] = 0x80;
    memset(padded_msg + original_byte_length + 1, 0, k);

    uint64_t length_bits = (uint64_t)original_byte_length * 8;
    // Write 128-bit length: high 64 bits are zero (for messages < 2^64 bits)
    for (int i = 0; i < 8; ++i) {
        padded_msg[padded_length - 16 + i] = 0;
    }
    for (int i = 0; i < 8; ++i) {
        padded_msg[padded_length - 8 + i] = (length_bits >> (56 - 8 * i)) & 0xFF;
    }

    uint64_t h[8];
    memcpy(h, initial_hash, sizeof(initial_hash));

    size_t num_blocks = padded_length / 128;
    for (size_t i = 0; i < num_blocks; ++i) {
        const unsigned char *block = padded_msg + i * 128;
        uint64_t W[80];

        for (int t = 0; t < 16; ++t) {
            W[t] = ((uint64_t)block[t * 8] << 56) |
                   ((uint64_t)block[t * 8 + 1] << 48) |
                   ((uint64_t)block[t * 8 + 2] << 40) |
                   ((uint64_t)block[t * 8 + 3] << 32) |
                   ((uint64_t)block[t * 8 + 4] << 24) |
                   ((uint64_t)block[t * 8 + 5] << 16) |
                   ((uint64_t)block[t * 8 + 6] << 8) |
                   ((uint64_t)block[t * 8 + 7]);
        }

        for (int t = 16; t < 80; ++t) {
            W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
        }

        uint64_t a = h[0];
        uint64_t b = h[1];
        uint64_t c = h[2];
        uint64_t d = h[3];
        uint64_t e = h[4];
        uint64_t f = h[5];
        uint64_t g = h[6];
        uint64_t h_i = h[7];

        for (int t = 0; t < 80; ++t) {
            uint64_t T1 = h_i + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
            uint64_t T2 = Sigma0(a) + Maj(a, b, c);
            h_i = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_i;
    }

    // SHA-384 uses only the first 6 words (384 bits) of the final hash
    for (int i = 0; i < 6; ++i) {
        uint64_t hi = h[i];
        digest[i * 8 + 0] = (hi >> 56) & 0xFF;
        digest[i * 8 + 1] = (hi >> 48) & 0xFF;
        digest[i * 8 + 2] = (hi >> 40) & 0xFF;
        digest[i * 8 + 3] = (hi >> 32) & 0xFF;
        digest[i * 8 + 4] = (hi >> 24) & 0xFF;
        digest[i * 8 + 5] = (hi >> 16) & 0xFF;
        digest[i * 8 + 6] = (hi >> 8) & 0xFF;
        digest[i * 8 + 7] = hi & 0xFF;
    }

    free(padded_msg);
}