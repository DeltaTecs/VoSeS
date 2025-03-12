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