#include "tls-gcm-extract.h"
#include "../cuda_util.h"
#include "../crypto/kdf.h"
#include "../crypto/gcm128.h"
#include "../crypto/gcm256.h"
#include "../crypto/aes128.h"
#include "../crypto/aes256.h"

#define KEY_LEN_128 16
#define KEY_LEN_256 32
#define IV_LEN 4
#define NONCE_LEN 12
#define QUIC_SAMPLE_LEN 16
#define QUIC_PN_MAX_LEN 4
#define QUIC_MAX_HEADER_LEN 256

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

__device__ bool cuda_match_quic_app_traffic_secret_0_gcm128_sha256(const unsigned char* d_app_traffic_secret_0, short app_traffic_secret_len,
                                    const unsigned char* d_packet, short packet_length, short pn_offset) {
    unsigned char l_key[KEY_LEN_128];
    unsigned char l_iv[NONCE_LEN];
    unsigned char l_hp_key[KEY_LEN_128];
    unsigned char l_nonce[NONCE_LEN];

    // Derive QUIC packet protection and header protection keys.
    cuda_derive_quic_keys_128(d_app_traffic_secret_0, app_traffic_secret_len, l_key, l_iv, l_hp_key);

    if (pn_offset < 0 || pn_offset >= packet_length) {
        return false;
    }
    // Header protection sample is 16 bytes starting at pn_offset + 4.
    const int sample_offset = pn_offset + 4;
    if (packet_length < sample_offset + QUIC_SAMPLE_LEN) {
        return false;
    }

    unsigned char mask[QUIC_SAMPLE_LEN];
    cuda_array_copy(mask, d_packet + sample_offset, QUIC_SAMPLE_LEN);
    struct AES128_ctx hp_ctx;
    cuda_AES128_init_ctx(&hp_ctx, l_hp_key);
    // AES-ECB of the sample yields the header protection mask.
    cuda_AES128_ECB_encrypt(&hp_ctx, mask);

    unsigned char first_byte = d_packet[0];
    bool is_long_header = (first_byte & 0x80) != 0;
    // Unprotect first byte to recover header form and PN length bits.
    unsigned char unprotected_first = first_byte ^ (mask[0] & (is_long_header ? 0x0f : 0x1f));
    short pn_len = (unprotected_first & 0x03) + 1;
    if (pn_len < 1 || pn_len > QUIC_PN_MAX_LEN) {
        return false;
    }

    // Copy header and unprotect the packet number bytes.
    short header_len = pn_offset + pn_len;
    if (header_len > packet_length || header_len > QUIC_MAX_HEADER_LEN) {
        return false;
    }

    unsigned char l_header[QUIC_MAX_HEADER_LEN];
    cuda_array_copy(l_header, d_packet, header_len);
    l_header[0] = unprotected_first;
    for (int i = 0; i < pn_len; i++) {
        l_header[pn_offset + i] ^= mask[i + 1];
    }

    // Reserved bits must be zero after unprotection.
    const unsigned char reserved_mask = is_long_header ? 0x0c : 0x18;
    if ((l_header[0] & reserved_mask) != 0) {
        return false;
    }

    // Decode the truncated packet number to build the nonce.
    uint32_t pn_value = 0;
    for (int i = 0; i < pn_len; i++) {
        pn_value = (pn_value << 8) | l_header[pn_offset + i];
    }

    // AEAD nonce = IV XOR packet number (low 32 bits).
    for (int i = 0; i < NONCE_LEN; i++) {
        l_nonce[i] = l_iv[i];
    }
    for (int i = 0; i < 4; i++) {
        l_nonce[NONCE_LEN - 1 - i] ^= (unsigned char)((pn_value >> (8 * i)) & 0xff);
    }

    // Ciphertext starts after the protected header; tag is appended.
    const unsigned char* d_ciphertext = d_packet + header_len;
    int ciphertext_length = packet_length - header_len;
    if (ciphertext_length < 16) {
        return false;
    }

    // Verify the AEAD tag with the unprotected header as AAD.
    return cuda_GCM_128_verify_tag(d_ciphertext, ciphertext_length,
                                    l_header, header_len,
                                    l_nonce, l_key);
}

__device__ bool cuda_match_quic_app_traffic_secret_0_gcm256_sha384(const unsigned char* d_app_traffic_secret_0, short app_traffic_secret_len,
                                    const unsigned char* d_packet, short packet_length, short pn_offset) {
    unsigned char l_key[KEY_LEN_256];
    unsigned char l_iv[NONCE_LEN];
    unsigned char l_hp_key[KEY_LEN_256];
    unsigned char l_nonce[NONCE_LEN];

    // Derive QUIC packet protection and header protection keys.
    cuda_derive_quic_keys_256(d_app_traffic_secret_0, app_traffic_secret_len, l_key, l_iv, l_hp_key);

    if (pn_offset < 0 || pn_offset >= packet_length) {
        return false;
    }
    // Header protection sample is 16 bytes starting at pn_offset + 4.
    const int sample_offset = pn_offset + 4;
    if (packet_length < sample_offset + QUIC_SAMPLE_LEN) {
        return false;
    }

    unsigned char mask[QUIC_SAMPLE_LEN];
    cuda_array_copy(mask, d_packet + sample_offset, QUIC_SAMPLE_LEN);
    struct AES256_ctx hp_ctx;
    cuda_AES256_init_ctx(&hp_ctx, l_hp_key);
    // AES-ECB of the sample yields the header protection mask.
    cuda_AES256_ECB_encrypt(&hp_ctx, mask);

    unsigned char first_byte = d_packet[0];
    bool is_long_header = (first_byte & 0x80) != 0;
    // Unprotect first byte to recover header form and PN length bits.
    unsigned char unprotected_first = first_byte ^ (mask[0] & (is_long_header ? 0x0f : 0x1f));
    short pn_len = (unprotected_first & 0x03) + 1;
    if (pn_len < 1 || pn_len > QUIC_PN_MAX_LEN) {
        return false;
    }

    // Copy header and unprotect the packet number bytes.
    short header_len = pn_offset + pn_len;
    if (header_len > packet_length || header_len > QUIC_MAX_HEADER_LEN) {
        return false;
    }

    unsigned char l_header[QUIC_MAX_HEADER_LEN];
    cuda_array_copy(l_header, d_packet, header_len);
    l_header[0] = unprotected_first;
    for (int i = 0; i < pn_len; i++) {
        l_header[pn_offset + i] ^= mask[i + 1];
    }

    // Reserved bits must be zero after unprotection.
    const unsigned char reserved_mask = is_long_header ? 0x0c : 0x18;
    if ((l_header[0] & reserved_mask) != 0) {
        return false;
    }

    // Decode the truncated packet number to build the nonce.
    uint32_t pn_value = 0;
    for (int i = 0; i < pn_len; i++) {
        pn_value = (pn_value << 8) | l_header[pn_offset + i];
    }

    // AEAD nonce = IV XOR packet number (low 32 bits).
    for (int i = 0; i < NONCE_LEN; i++) {
        l_nonce[i] = l_iv[i];
    }
    for (int i = 0; i < 4; i++) {
        l_nonce[NONCE_LEN - 1 - i] ^= (unsigned char)((pn_value >> (8 * i)) & 0xff);
    }

    // Ciphertext starts after the protected header; tag is appended.
    const unsigned char* d_ciphertext = d_packet + header_len;
    int ciphertext_length = packet_length - header_len;
    if (ciphertext_length < 16) {
        return false;
    }

    // Verify the AEAD tag with the unprotected header as AAD.
    return cuda_GCM_256_verify_tag(d_ciphertext, ciphertext_length,
                                    l_header, header_len,
                                    l_nonce, l_key);
}
