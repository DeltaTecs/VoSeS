#include "quic-gcm-extract.h"
#include "../../cuda_util.h"
#include "../../crypto/kdf.h"
#include "../../crypto/gcm128.h"
#include "../../crypto/gcm256.h"
#include "../../crypto/aes128.h"
#include "../../crypto/aes256.h"

#define KEY_LEN_128 16
#define KEY_LEN_256 32
#define NONCE_LEN 12
#define QUIC_SAMPLE_LEN 16
#define QUIC_PN_MAX_LEN 4
#define QUIC_MAX_HEADER_LEN 256

__device__ bool cuda_match_quic_app_traffic_secret_0_gcm128_sha256(const unsigned char* d_app_traffic_secret_0, short app_traffic_secret_len,
                                    const unsigned char* d_packet, short packet_length, short pn_offset) {
    unsigned char l_key[KEY_LEN_128];
    unsigned char l_iv[NONCE_LEN];
    unsigned char l_hp_key[KEY_LEN_128];
    unsigned char l_nonce[NONCE_LEN];

    cuda_derive_quic_keys_128(d_app_traffic_secret_0, app_traffic_secret_len, l_key, l_iv, l_hp_key);

    if (pn_offset < 0 || pn_offset >= packet_length) {
        return false;
    }
    const int sample_offset = pn_offset + 4;
    if (packet_length < sample_offset + QUIC_SAMPLE_LEN) {
        return false;
    }

    unsigned char mask[QUIC_SAMPLE_LEN];
    cuda_array_copy(mask, d_packet + sample_offset, QUIC_SAMPLE_LEN);
    struct AES128_ctx hp_ctx;
    cuda_AES128_init_ctx(&hp_ctx, l_hp_key);
    cuda_AES128_ECB_encrypt(&hp_ctx, mask);

    unsigned char first_byte = d_packet[0];
    bool is_long_header = (first_byte & 0x80) != 0;
    unsigned char unprotected_first = first_byte ^ (mask[0] & (is_long_header ? 0x0f : 0x1f));
    short pn_len = (unprotected_first & 0x03) + 1;
    if (pn_len < 1 || pn_len > QUIC_PN_MAX_LEN) {
        return false;
    }

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

    const unsigned char reserved_mask = is_long_header ? 0x0c : 0x18;
    if ((l_header[0] & reserved_mask) != 0) {
        return false;
    }

    uint32_t pn_value = 0;
    for (int i = 0; i < pn_len; i++) {
        pn_value = (pn_value << 8) | l_header[pn_offset + i];
    }

    for (int i = 0; i < NONCE_LEN; i++) {
        l_nonce[i] = l_iv[i];
    }
    for (int i = 0; i < 4; i++) {
        l_nonce[NONCE_LEN - 1 - i] ^= (unsigned char)((pn_value >> (8 * i)) & 0xff);
    }

    const unsigned char* d_ciphertext = d_packet + header_len;
    int ciphertext_length = packet_length - header_len;
    if (ciphertext_length < 16) {
        return false;
    }

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

    cuda_derive_quic_keys_256(d_app_traffic_secret_0, app_traffic_secret_len, l_key, l_iv, l_hp_key);

    if (pn_offset < 0 || pn_offset >= packet_length) {
        return false;
    }
    const int sample_offset = pn_offset + 4;
    if (packet_length < sample_offset + QUIC_SAMPLE_LEN) {
        return false;
    }

    unsigned char mask[QUIC_SAMPLE_LEN];
    cuda_array_copy(mask, d_packet + sample_offset, QUIC_SAMPLE_LEN);
    struct AES256_ctx hp_ctx;
    cuda_AES256_init_ctx(&hp_ctx, l_hp_key);
    cuda_AES256_ECB_encrypt(&hp_ctx, mask);

    unsigned char first_byte = d_packet[0];
    bool is_long_header = (first_byte & 0x80) != 0;
    unsigned char unprotected_first = first_byte ^ (mask[0] & (is_long_header ? 0x0f : 0x1f));
    short pn_len = (unprotected_first & 0x03) + 1;
    if (pn_len < 1 || pn_len > QUIC_PN_MAX_LEN) {
        return false;
    }

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

    const unsigned char reserved_mask = is_long_header ? 0x0c : 0x18;
    if ((l_header[0] & reserved_mask) != 0) {
        return false;
    }

    uint32_t pn_value = 0;
    for (int i = 0; i < pn_len; i++) {
        pn_value = (pn_value << 8) | l_header[pn_offset + i];
    }

    for (int i = 0; i < NONCE_LEN; i++) {
        l_nonce[i] = l_iv[i];
    }
    for (int i = 0; i < 4; i++) {
        l_nonce[NONCE_LEN - 1 - i] ^= (unsigned char)((pn_value >> (8 * i)) & 0xff);
    }

    const unsigned char* d_ciphertext = d_packet + header_len;
    int ciphertext_length = packet_length - header_len;
    if (ciphertext_length < 16) {
        return false;
    }

    return cuda_GCM_256_verify_tag(d_ciphertext, ciphertext_length,
                                    l_header, header_len,
                                    l_nonce, l_key);
}
