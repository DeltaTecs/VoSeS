#include "gcm128.h"

// Multiply two 128-bit numbers X and Y in GF(2^128) using the
// polynomial x^128 + x^7 + x^2 + x + 1. The result is written into result.
void multiply_gf128(const uint8_t *X, const uint8_t *Y, uint8_t *result) {
    uint8_t Z[16] = {0};  // Accumulator for the result, initially 0
    uint8_t V[16];
    array_copy(V, X, 16);

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
    array_copy(result, Z, 16);
}

// This function verifies the authentication tag of AES-128 GCM as used in TLS 1.2.
// The input parameter 'ciphertext' is assumed to have the tag appended (last 16 bytes).
bool GCM_128_verify_tag(const unsigned char* ciphertext, int ciphertext_length, 
                          const unsigned char* aad, int aad_length, 
                          const unsigned char* nonce, const unsigned char* key)
{
    // Check that ciphertext length is at least 16 bytes (for the tag)
    if (ciphertext_length < 16) return false;
    int actual_ciphertext_length = ciphertext_length - 16;
    const unsigned char *provided_tag = ciphertext + actual_ciphertext_length;

    // Initialize AES context with the given key.
    struct AES_ctx ctx;
    cuda_AES_init_ctx(&ctx, key);

    // Compute hash subkey H = AES_Encrypt(0^128)
    unsigned char H[16] = {0};
    cuda_AES_ECB_encrypt(&ctx, H);

    // Construct J0 from nonce.
    // For TLS 1.2, nonce is typically 12 bytes.
    // J0 = nonce || 0x00000001
    unsigned char J0[16] = {0};
    array_copy(J0, nonce, 12);
    J0[15] = 0x01;

    // Compute GHASH over AAD and the ciphertext (without the tag)
    unsigned char S[16] = {0};  // GHASH accumulator starts at 0

    // Process AAD (if any)
    int aad_blocks = (aad_length + 15) / 16;
    for (int i = 0; i < aad_blocks; i++) {
        unsigned char block[16] = {0};
        int copy_len = ((aad_length - i * 16) > 16) ? 16 : (aad_length - i * 16);
        array_copy(block, aad + i * 16, copy_len);
        for (int j = 0; j < 16; j++) {
            S[j] ^= block[j];
        }
        multiply_gf128(S, H, S);
    }

    // Process ciphertext (the actual encrypted data, excluding the tag)
    int ct_blocks = (actual_ciphertext_length + 15) / 16;
    for (int i = 0; i < ct_blocks; i++) {
        unsigned char block[16] = {0};
        int copy_len = ((actual_ciphertext_length - i * 16) > 16) ? 16 : (actual_ciphertext_length - i * 16);
        array_copy(block, ciphertext + i * 16, copy_len);
        for (int j = 0; j < 16; j++) {
            S[j] ^= block[j];
        }
        multiply_gf128(S, H, S);
    }

    // Process the length block: 64-bit lengths (in bits) of AAD and ciphertext (big-endian)
    unsigned char len_block[16] = {0};
    uint64_t aad_bits = ((uint64_t)aad_length) * 8;
    uint64_t ct_bits  = ((uint64_t)actual_ciphertext_length) * 8;
    for (int i = 0; i < 8; i++) {
        len_block[i]    = (aad_bits >> (56 - 8 * i)) & 0xff;
        len_block[i + 8]= (ct_bits  >> (56 - 8 * i)) & 0xff;
    }
    for (int j = 0; j < 16; j++) {
        S[j] ^= len_block[j];
    }
    multiply_gf128(S, H, S);

    // Compute E(K, J0)
    unsigned char E_J0[16];
    array_copy(E_J0, J0, 16);
    cuda_AES_ECB_encrypt(&ctx, E_J0);

    // The expected tag is computed as: tag = E(K, J0) XOR S
    unsigned char computed_tag[16];
    for (int i = 0; i < 16; i++) {
        computed_tag[i] = E_J0[i] ^ S[i];
    }

    // Constant-time comparison of computed_tag and provided_tag
    volatile unsigned char diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ provided_tag[i];
    }

    return (diff == 0);
}