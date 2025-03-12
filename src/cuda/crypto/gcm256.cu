#include "gcm256.h"
#include "aes256.h"
#include "../util.h"

// This function verifies the authentication tag of AES-256 GCM as used in TLS 1.2.
// The input parameter 'd_ciphertext' is assumed to have the tag appended (last 16 bytes).
__device__ bool cuda_GCM_256_verify_tag(const unsigned char* d_ciphertext, int ciphertext_length, 
                          const unsigned char* d_aad, int aad_length, 
                          const unsigned char* d_nonce, const unsigned char* d_key)
{
    // Ensure that the ciphertext is at least 16 bytes (for the tag)
    if (ciphertext_length < 16) return false;
    int actual_ciphertext_length = ciphertext_length - 16;
    const unsigned char *provided_tag = d_ciphertext + actual_ciphertext_length;

    // Initialize AES256 context with the given key (assumed to be 256 bits)
    struct AES256_ctx ctx;
    cuda_AES256_init_ctx(&ctx, d_key);

    // Compute hash subkey H = AES256_Encrypt(0^128)
    unsigned char H[16] = {0};
    cuda_AES256_ECB_encrypt(&ctx, H);

    // Construct J0 from d_nonce.
    // For TLS 1.2, d_nonce is typically 12 bytes, so J0 = d_nonce || 0x00000001.
    unsigned char J0[16] = {0};
    cuda_array_copy(J0, d_nonce, 12);
    J0[15] = 0x01;

    // Compute GHASH over AAD and the ciphertext (excluding the tag)
    unsigned char S[16] = {0};  // GHASH accumulator starts at 0

    // Process Additional Authenticated Data (AAD), if any.
    int aad_blocks = (aad_length + 15) / 16;
    for (int i = 0; i < aad_blocks; i++) {
        unsigned char block[16] = {0};
        int copy_len = ((aad_length - i * 16) > 16) ? 16 : (aad_length - i * 16);
        cuda_array_copy(block, d_aad + i * 16, copy_len);
        for (int j = 0; j < 16; j++) {
            S[j] ^= block[j];
        }
        cuda_multiply_gf128(S, H, S);
    }

    // Process the ciphertext (excluding the tag)
    int ct_blocks = (actual_ciphertext_length + 15) / 16;
    for (int i = 0; i < ct_blocks; i++) {
        unsigned char block[16] = {0};
        int copy_len = ((actual_ciphertext_length - i * 16) > 16) ? 16 : (actual_ciphertext_length - i * 16);
        cuda_array_copy(block, d_ciphertext + i * 16, copy_len);
        for (int j = 0; j < 16; j++) {
            S[j] ^= block[j];
        }
        cuda_multiply_gf128(S, H, S);
    }

    // Process the length block: 64-bit lengths (in bits) of AAD and ciphertext (big-endian).
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
    cuda_multiply_gf128(S, H, S);

    // Compute E(K, J0)
    unsigned char E_J0[16];
    cuda_array_copy(E_J0, J0, 16);
    cuda_AES256_ECB_encrypt(&ctx, E_J0);

    // The expected tag is computed as: tag = E(K, J0) XOR S.
    unsigned char computed_tag[16];
    for (int i = 0; i < 16; i++) {
        computed_tag[i] = E_J0[i] ^ S[i];
    }

    // Perform a constant-time comparison of the computed tag with the provided tag.
    volatile unsigned char diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ provided_tag[i];
    }

    return (diff == 0);
}