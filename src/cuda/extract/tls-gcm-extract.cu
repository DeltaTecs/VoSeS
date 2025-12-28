#include "tls-gcm-extract.h"
#include "../crypto/kdf.h"
#include "../crypto/gcm128.h"
#include "../crypto/gcm256.h"

#define KEY_LEN_128 16
#define KEY_LEN_256 32
#define IV_LEN 4
#define NONCE_LEN 12

__device__ bool cuda_match_master_secret_gcm128_sha256(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_aad, short aad_length, unsigned char* d_chiphertext, short ciphertext_length) {

    unsigned char l_client_write_key[KEY_LEN_128];
    unsigned char l_server_write_key[KEY_LEN_128];
    unsigned char l_client_iv[IV_LEN];
    unsigned char l_server_iv[IV_LEN];
    unsigned char l_client_nonce[NONCE_LEN];

    cuda_derive_tls12_keys_128(d_master_secret, master_secret_len,
                        d_client_random, d_server_random,
                            l_client_write_key, l_server_write_key,
                            l_client_iv, l_server_iv);

    cuda_build_tls12_aes_gcm_nonce(seq_num, l_client_iv, l_client_nonce);

    // Call the verification function.
    return cuda_GCM_128_verify_tag(d_chiphertext, ciphertext_length,
                                    d_aad, aad_length,
                                    l_client_nonce, l_client_write_key);
 }

 __device__ bool cuda_match_master_secret_gcm128_sha256_plaintxt_cmp(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_plaintext, short plaintext_length, unsigned char* d_chiphertext, short ciphertext_length) {

    unsigned char l_client_write_key[KEY_LEN_128];
    unsigned char l_server_write_key[KEY_LEN_128];
    unsigned char l_client_iv[IV_LEN];
    unsigned char l_server_iv[IV_LEN];
    unsigned char l_client_nonce[NONCE_LEN];

    cuda_derive_tls12_keys_128(d_master_secret, master_secret_len,
                        d_client_random, d_server_random,
                            l_client_write_key, l_server_write_key,
                            l_client_iv, l_server_iv);

    cuda_build_tls12_aes_gcm_nonce(seq_num, l_client_iv, l_client_nonce);

    // Call the verification function.
    return cuda_GCM_128_cmp_plaintxt_block(d_chiphertext, ciphertext_length,
                                    d_plaintext, plaintext_length,
                                    l_client_nonce, l_client_write_key);
 }

 __device__ bool cuda_match_master_secret_gcm256_sha384(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_aad, short aad_length, unsigned char* d_chiphertext, short ciphertext_length) {

    unsigned char l_client_write_key[KEY_LEN_256];
    unsigned char l_server_write_key[KEY_LEN_256];
    unsigned char l_client_iv[IV_LEN];
    unsigned char l_server_iv[IV_LEN];
    unsigned char l_client_nonce[NONCE_LEN];

    cuda_derive_tls12_keys_256(d_master_secret, master_secret_len,
                        d_client_random, d_server_random,
                            l_client_write_key, l_server_write_key,
                            l_client_iv, l_server_iv);

    cuda_build_tls12_aes_gcm_nonce(seq_num, l_client_iv, l_client_nonce);

    // Call the verification function.
    return cuda_GCM_256_verify_tag(d_chiphertext, ciphertext_length,
                                    d_aad, aad_length,
                                    l_client_nonce, l_client_write_key);
 }

  __device__ bool cuda_match_master_secret_gcm256_sha384_plaintxt_cmp(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_plaintext, short plaintext_length, unsigned char* d_chiphertext, short ciphertext_length) {

    unsigned char l_client_write_key[KEY_LEN_256];
    unsigned char l_server_write_key[KEY_LEN_256];
    unsigned char l_client_iv[IV_LEN];
    unsigned char l_server_iv[IV_LEN];
    unsigned char l_client_nonce[NONCE_LEN];

    cuda_derive_tls12_keys_256(d_master_secret, master_secret_len,
                        d_client_random, d_server_random,
                            l_client_write_key, l_server_write_key,
                            l_client_iv, l_server_iv);

    cuda_build_tls12_aes_gcm_nonce(seq_num, l_client_iv, l_client_nonce);


    return cuda_GCM_256_cmp_plaintxt_block(d_chiphertext, ciphertext_length,
                                    d_plaintext, plaintext_length,
                                    l_client_nonce, l_client_write_key);
}

// computes the TLS 1.3 encryption keys based of the supplied applcation traffic secret and tries to verify the GCM tag of the
// specified ciphertext, along the specified AAD and seq num
__device__ bool cuda_match_app_traffic_secret_0_gcm128_sha256(const unsigned char* d_app_traffic_secret_0, short app_traffic_secret_len,
                                    uint64_t seq_num, unsigned char* d_aad, short aad_length,
                                    unsigned char* d_chiphertext, short ciphertext_length) {
    unsigned char l_key[KEY_LEN_128];
    unsigned char l_iv[NONCE_LEN];
    unsigned char l_nonce[NONCE_LEN];

    cuda_derive_tls13_key_128(d_app_traffic_secret_0, app_traffic_secret_len, l_key, l_iv);

    // Build TLS 1.3 nonce: XOR IV with the padded sequence number (big-endian).
    for (int i = 0; i < NONCE_LEN; i++) {
        l_nonce[i] = l_iv[i];
    }
    for (int i = 0; i < 8; i++) {
        l_nonce[NONCE_LEN - 1 - i] ^= (unsigned char)((seq_num >> (8 * i)) & 0xff);
    }

    // Call the verification function.
    return cuda_GCM_128_verify_tag(d_chiphertext, ciphertext_length,
                                    d_aad, aad_length,
                                    l_nonce, l_key);
}

__device__ bool cuda_match_app_traffic_secret_0_gcm256_sha384(const unsigned char* d_app_traffic_secret_0, short app_traffic_secret_len,
                                    uint64_t seq_num, unsigned char* d_aad, short aad_length,
                                    unsigned char* d_chiphertext, short ciphertext_length) {
    unsigned char l_key[KEY_LEN_256];
    unsigned char l_iv[NONCE_LEN];
    unsigned char l_nonce[NONCE_LEN];

    cuda_derive_tls13_key_256(d_app_traffic_secret_0, app_traffic_secret_len, l_key, l_iv);

    // Build TLS 1.3 nonce: XOR IV with the padded sequence number (big-endian).
    for (int i = 0; i < NONCE_LEN; i++) {
        l_nonce[i] = l_iv[i];
    }
    for (int i = 0; i < 8; i++) {
        l_nonce[NONCE_LEN - 1 - i] ^= (unsigned char)((seq_num >> (8 * i)) & 0xff);
    }

    return cuda_GCM_256_verify_tag(d_chiphertext, ciphertext_length,
                                    d_aad, aad_length,
                                    l_nonce, l_key);
}
