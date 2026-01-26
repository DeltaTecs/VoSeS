#include "tls13-gcm-extract.h"
#include "../../crypto/kdf.h"
#include "../../crypto/gcm128.h"
#include "../../crypto/gcm256.h"

#define KEY_LEN_128 16
#define KEY_LEN_256 32
#define NONCE_LEN 12

__device__ bool cuda_match_app_traffic_secret_0_gcm128_sha256(const unsigned char* d_app_traffic_secret_0, short app_traffic_secret_len,
                                    uint64_t seq_num, unsigned char* d_aad, short aad_length,
                                    unsigned char* d_chiphertext, short ciphertext_length) {
    unsigned char l_key[KEY_LEN_128];
    unsigned char l_iv[NONCE_LEN];
    unsigned char l_nonce[NONCE_LEN];

    cuda_derive_tls13_key_128(d_app_traffic_secret_0, app_traffic_secret_len, l_key, l_iv);

    for (int i = 0; i < NONCE_LEN; i++) {
        l_nonce[i] = l_iv[i];
    }
    for (int i = 0; i < 8; i++) {
        l_nonce[NONCE_LEN - 1 - i] ^= (unsigned char)((seq_num >> (8 * i)) & 0xff);
    }

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
