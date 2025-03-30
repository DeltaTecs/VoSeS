#include "gcm128.h"
#include "aes128.h"
#include "../cuda_util.h"

// This function verifies the authentication tag of AES-128 GCM as used in TLS 1.2.
// The input parameter 'd_ciphertext' is assumed to have the tag appended (last 16 bytes).
__device__ bool cuda_GCM_128_verify_tag(const unsigned char* d_ciphertext, int ciphertext_length, 
                          const unsigned char* d_aad, int aad_length, 
                          const unsigned char* d_nonce, const unsigned char* d_key)
{
    // Check that d_ciphertext length is at least 16 bytes (for the tag)
    if (ciphertext_length < 16) return false;
    int actual_ciphertext_length = ciphertext_length - 16;
    const unsigned char *provided_tag = d_ciphertext + actual_ciphertext_length;

    // Initialize AES context with the given d_key.
    struct AES128_ctx ctx;
    cuda_AES128_init_ctx(&ctx, d_key);

    // Compute hash subkey H = AES_Encrypt(0^128)
    unsigned char H[16] = {0};
    cuda_AES128_ECB_encrypt(&ctx, H);

    // Construct J0 from d_nonce.
    // For TLS 1.2, d_nonce is typically 12 bytes.
    // J0 = d_nonce || 0x00000001
    unsigned char J0[16] = {0};
    cuda_array_copy(J0, d_nonce, 12);
    J0[15] = 0x01;

    // Compute GHASH over AAD and the d_ciphertext (without the tag)
    unsigned char S[16] = {0};  // GHASH accumulator starts at 0

    // Process AAD (if any)
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

    // Process d_ciphertext (the actual encrypted data, excluding the tag)
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

    // Process the length block: 64-bit lengths (in bits) of AAD and d_ciphertext (big-endian)
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
    cuda_AES128_ECB_encrypt(&ctx, E_J0);

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

__device__ bool cuda_GCM_128_cmp_plaintxt_block(const unsigned char* d_ciphertext, int ciphertext_length, 
                          const unsigned char* d_expected_plaintext, char expected_plaintext_length, 
                          const unsigned char* d_nonce, const unsigned char* d_key)
{
    // Ensure that the ciphertext is at least 16 bytes
    if (ciphertext_length < 16) return false;
    // Ensure that the plaintext is actualy max a block
    if (expected_plaintext_length > 16) {
        printf("ERROR to much plain text given to compare\n");    
        return false;
    }

    // Initialize AES128 context with the given key (assumed to be 128 bits)
    struct AES128_ctx ctx;
    cuda_AES128_init_ctx(&ctx, d_key);

    // Construct J1 from d_nonce.
    // For TLS 1.2, d_nonce is typically 12 bytes, so J1 = d_nonce || 0x00000002.
    unsigned char J1[16] = {0};
    cuda_array_copy(J1, d_nonce, 12);
    J1[15] = 0x02;

    // Compute E(K, J0)
    unsigned char E_J1[16];
    cuda_array_copy(E_J1, J1, 16);
    cuda_AES128_ECB_encrypt(&ctx, E_J1);

    // compare with plaintext
    volatile unsigned char diff = 0;
    for (int i = 0; i < expected_plaintext_length; i++) {
        diff |= d_expected_plaintext[i] ^ d_ciphertext[i] ^ E_J1[i];
    }

    return (diff == 0);
}