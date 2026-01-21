#include "tls12-gcm-extract.h"
#include "../../crypto/kdf.h"
#include "../../crypto/gcm128.h"
#include "../../crypto/gcm256.h"

#define KEY_LEN_128 16
#define KEY_LEN_256 32
#define IV_LEN 4
#define NONCE_LEN 12

__device__ bool cuda_match_master_secret_gcm128_sha256(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_aad, short aad_length, unsigned char* d_chiphertext, short ciphertext_length) {

    // TLS 1.2 AES-GCM record fragment layout:
    //   nonce_explicit(8) || ciphertext || tag(16)
    if (ciphertext_length < 8 + 16) return false;

    unsigned char l_client_write_key[KEY_LEN_128];
    unsigned char l_server_write_key[KEY_LEN_128];
    unsigned char l_client_iv[IV_LEN];
    unsigned char l_server_iv[IV_LEN];
    unsigned char l_client_nonce[NONCE_LEN];

    cuda_derive_tls12_keys_128(d_master_secret, master_secret_len,
                        d_client_random, d_server_random,
                            l_client_write_key, l_server_write_key,
                            l_client_iv, l_server_iv);

    // Build nonce as fixed_iv(4) || nonce_explicit(8)
    cuda_build_tls12_aes_gcm_nonce_from_explicit(d_chiphertext, l_client_iv, l_client_nonce);

    return cuda_GCM_128_verify_tag(d_chiphertext + 8, ciphertext_length - 8,
                                    d_aad, aad_length,
                                    l_client_nonce, l_client_write_key);
 }

 __device__ bool cuda_match_master_secret_gcm128_sha256_plaintxt_cmp(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_plaintext, short plaintext_length, unsigned char* d_chiphertext, short ciphertext_length) {

    if (ciphertext_length < 8 + 16) return false;

    unsigned char l_client_write_key[KEY_LEN_128];
    unsigned char l_server_write_key[KEY_LEN_128];
    unsigned char l_client_iv[IV_LEN];
    unsigned char l_server_iv[IV_LEN];
    unsigned char l_client_nonce[NONCE_LEN];

    cuda_derive_tls12_keys_128(d_master_secret, master_secret_len,
                        d_client_random, d_server_random,
                            l_client_write_key, l_server_write_key,
                            l_client_iv, l_server_iv);

    cuda_build_tls12_aes_gcm_nonce_from_explicit(d_chiphertext, l_client_iv, l_client_nonce);

    return cuda_GCM_128_cmp_plaintxt_block(d_chiphertext + 8, ciphertext_length - 8,
                                    d_plaintext, plaintext_length,
                                    l_client_nonce, l_client_write_key);
 }

 __device__ bool cuda_match_master_secret_gcm256_sha384(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_aad, short aad_length, unsigned char* d_chiphertext, short ciphertext_length) {

    if (ciphertext_length < 8 + 16) return false;

    unsigned char l_client_write_key[KEY_LEN_256];
    unsigned char l_server_write_key[KEY_LEN_256];
    unsigned char l_client_iv[IV_LEN];
    unsigned char l_server_iv[IV_LEN];
    unsigned char l_client_nonce[NONCE_LEN];

    cuda_derive_tls12_keys_256(d_master_secret, master_secret_len,
                        d_client_random, d_server_random,
                            l_client_write_key, l_server_write_key,
                            l_client_iv, l_server_iv);

    cuda_build_tls12_aes_gcm_nonce_from_explicit(d_chiphertext, l_client_iv, l_client_nonce);

    return cuda_GCM_256_verify_tag(d_chiphertext + 8, ciphertext_length - 8,
                                    d_aad, aad_length,
                                    l_client_nonce, l_client_write_key);
 }

  __device__ bool cuda_match_master_secret_gcm256_sha384_plaintxt_cmp(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_plaintext, short plaintext_length, unsigned char* d_chiphertext, short ciphertext_length) {

        if (ciphertext_length < 8 + 16) return false;

    unsigned char l_client_write_key[KEY_LEN_256];
    unsigned char l_server_write_key[KEY_LEN_256];
    unsigned char l_client_iv[IV_LEN];
    unsigned char l_server_iv[IV_LEN];
    unsigned char l_client_nonce[NONCE_LEN];

    cuda_derive_tls12_keys_256(d_master_secret, master_secret_len,
                        d_client_random, d_server_random,
                            l_client_write_key, l_server_write_key,
                            l_client_iv, l_server_iv);

    cuda_build_tls12_aes_gcm_nonce_from_explicit(d_chiphertext, l_client_iv, l_client_nonce);

    return cuda_GCM_256_cmp_plaintxt_block(d_chiphertext + 8, ciphertext_length - 8,
                                    d_plaintext, plaintext_length,
                                    l_client_nonce, l_client_write_key);
 }
