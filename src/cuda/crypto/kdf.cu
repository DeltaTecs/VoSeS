#include "kdf.h"
#include "../cuda_util.h"
#include "hmac-sha256.h"
#include "hmac-sha384.h"

// p_hash_sha384 computes the output of the TLS P_SHA384 function.
// It repeatedly computes HMAC(secret, A(i) || seed) where A(0)=seed and
// A(i) = HMAC(secret, A(i-1)). The outputs are concatenated until out_len bytes are produced.
__device__ void cuda_p_hash_sha384(const unsigned char *d_secret, short secret_len,
                   const unsigned char *d_seed, short seed_len,
                   unsigned char *d_out, short out_len)
{
    unsigned char A[48];        // A(1) initially; HMAC-SHA384 produces 48 bytes
    unsigned char hmac_buf[48];
    short pos = 0;
    
    if (seed_len > 80) {
        printf("ERROR seed length > 80 is not supported\n");
        return;
    }

    // A(1) = HMAC(secret, seed)
    cuda_hmac_sha384_128data(d_secret, secret_len, d_seed, seed_len, A);

    while (pos < out_len) {
        // Compute HMAC(secret, A(i) || seed)
        unsigned char A_seed[128];
        cuda_array_copy(A_seed, A, 48);
        cuda_array_copy(A_seed + 48, d_seed, seed_len);
        cuda_hmac_sha384_128data(d_secret, secret_len, A_seed, 48 + seed_len, hmac_buf);
        
        // Copy as many bytes as needed
        short bytes_to_copy = (out_len - pos < 48) ? (out_len - pos) : 48;
        cuda_array_copy(d_out + pos, hmac_buf, bytes_to_copy);
        pos += bytes_to_copy;
        
        // Next A = HMAC(secret, A)
        cuda_hmac_sha384_128data(d_secret, secret_len, A, 48, A);
    }
}

// p_hash_sha256 computes the output of the TLS P_SHA256 function.
// It repeatedly computes HMAC(secret, A(i) || seed) where A(0)=seed and
// A(i) = HMAC(secret, A(i-1)). The outputs are concatenated until out_len bytes are produced.
__device__ void cuda_p_hash_sha256(const unsigned char *d_secret, short secret_len,
                   const unsigned char *d_seed, short seed_len,
                   unsigned char *d_out, short out_len)
{
    unsigned char A[32];        // A(1) initially; HMAC-SHA256 produces 32 bytes
    unsigned char hmac_buf[32];
    short pos = 0;

    if (seed_len > 80) {
        printf("ERROR seed length > 80 is not supported\n");
        return;
    }
    
    // A(1) = HMAC(secret, seed)
    cuda_hmac_sha256_128data(d_secret, secret_len, d_seed, seed_len, A);

    while (pos < out_len) {
        // Allocate a buffer for A(i) || seed
        short A_seed_len = 32 + seed_len;
        unsigned char A_seed[128];
        cuda_array_copy(A_seed, A, 32);
        cuda_array_copy(A_seed + 32, d_seed, seed_len);

        // Compute HMAC(secret, A(i) || seed)
        cuda_hmac_sha256_128data(d_secret, secret_len, A_seed, A_seed_len, hmac_buf);
        
        // Copy as many bytes as needed from the current HMAC output
        short bytes_to_copy = (out_len - pos < 32) ? (out_len - pos) : 32;
        cuda_array_copy(d_out + pos, hmac_buf, bytes_to_copy);
        pos += bytes_to_copy;
        
        // Compute next A = HMAC(secret, A)
        cuda_hmac_sha256_128data(d_secret, secret_len, A, 32, A);
    }
}

// This function implements the TLS 1.2 key expansion for AES-128-GCM-SHA256.
// It derives a 40-byte key block from the master secret, server random, and client random,
// then partitions it as follows:
//   client_write_key: first 16 bytes
//   server_write_key: next 16 bytes
//   client_iv: next 4 bytes
//   server_iv: next 4 bytes
__device__ void cuda_derive_tls12_keys_128(const unsigned char *d_master_secret, short master_secret_len,
                              const unsigned char d_client_random[32], const unsigned char d_server_random[32],
                              unsigned char *d_client_write_key, unsigned char *d_server_write_key,
                              unsigned char *d_client_iv, unsigned char *d_server_iv)
{
    const short key_block_len = 40;
    unsigned char key_block[40];

    // Prepare the seed: "key expansion" || server_random || client_random
    const char *label = "key expansion";
    const short label_len = 13;
    const short seed_len = label_len + 32 + 32;  // Assuming client_random and server_random are 32 bytes each
    unsigned char seed[128];  // Sufficiently large buffer
    cuda_array_copy(seed, (unsigned char*) label, label_len);
    cuda_array_copy(seed + label_len, d_server_random, 32);
    cuda_array_copy(seed + label_len + 32, d_client_random, 32);

    // Compute the key block using P_SHA256 with the master secret as the key
    cuda_p_hash_sha256(d_master_secret, master_secret_len, seed, seed_len, key_block, key_block_len);

    cuda_array_copy(d_client_write_key, key_block, 16);
    cuda_array_copy(d_server_write_key, key_block + 16, 16);
    cuda_array_copy(d_client_iv, key_block + 32, 4);
    cuda_array_copy(d_server_iv, key_block + 36, 4);
}

// hkdf_expand_sha256 implements HKDF-Expand using HMAC-SHA256.
__device__ void cuda_hkdf_expand_sha256(const unsigned char *d_secret, short secret_len,
                          const unsigned char *d_info, short info_len,
                          unsigned char *d_out, short out_len)
{
    const short hash_len = 32;
    unsigned char t[hash_len];
    short pos = 0;
    unsigned char counter = 1;

    if (info_len + 1 > 128) {
        printf("ERROR hkdf_expand_sha256 info length too large\n");
        return;
    }

    while (pos < out_len) {
        unsigned char data[128];
        short data_len = 0;

        if (pos != 0) {
            cuda_array_copy(data, t, hash_len);
            data_len += hash_len;
        }
        if (data_len + info_len + 1 > 128) {
            printf("ERROR hkdf_expand_sha256 info length too large\n");
            return;
        }
        cuda_array_copy(data + data_len, d_info, info_len);
        data_len += info_len;
        data[data_len++] = counter;

        cuda_hmac_sha256_128data(d_secret, secret_len, data, data_len, t);

        short bytes_to_copy = (out_len - pos < hash_len) ? (out_len - pos) : hash_len;
        cuda_array_copy(d_out + pos, t, bytes_to_copy);
        pos += bytes_to_copy;
        counter++;
    }
}

// Build a TLS 1.3 HKDF label with an empty context.
__device__ short cuda_build_hkdf_label(const char *label, short label_len, unsigned short length,
                          unsigned char *d_out, short out_capacity)
{
    const char *tls13_prefix = "tls13 ";
    const short prefix_len = 6;
    const short full_label_len = prefix_len + label_len;
    const short total_len = 2 + 1 + full_label_len + 1;
    short pos = 0;

    if (total_len > out_capacity) {
        printf("ERROR hkdf_label buffer too small\n");
        return 0;
    }

    d_out[pos++] = (unsigned char)((length >> 8) & 0xff);
    d_out[pos++] = (unsigned char)(length & 0xff);
    d_out[pos++] = (unsigned char)full_label_len;
    cuda_array_copy(d_out + pos, (const unsigned char *)tls13_prefix, prefix_len);
    pos += prefix_len;
    cuda_array_copy(d_out + pos, (const unsigned char *)label, label_len);
    pos += label_len;
    d_out[pos++] = 0x00;

    return total_len;
}

// This function implements the TLS 1.3 key expansion for AES-128-GCM-SHA256 application traffic secrets.
// It derives a 16-byte write key and a 12-byte IV from the application traffic secret using HKDF-Expand-Label.
//   write_key: 16 bytes
//   iv: 12 bytes
__device__ void cuda_derive_tls13_key_128(const unsigned char *d_app_traffic_secret_0, short d_app_traffic_secret_len,
                              unsigned char *d_key, unsigned char *d_iv)
{
    const short key_len = 16; // AES-128 key length
    const short iv_len = 12; // AES-128 IV length

    const char *key_label = "key";
    const short key_label_len = 3;
    const char *iv_label = "iv";
    const short iv_label_len = 2;
    const short hkdf_key_label_len = 2 + 1 + 6 + key_label_len + 1; // len(2) + label_len(1) + "tls13 "(6) + label + context_len(1)
    const short hkdf_iv_label_len = 2 + 1 + 6 + iv_label_len + 1; // len(2) + label_len(1) + "tls13 "(6) + label + context_len(1)
    unsigned char hkdf_key_label[hkdf_key_label_len];
    unsigned char hkdf_iv_label[hkdf_iv_label_len];

    short hkdf_key_label_actual_len = cuda_build_hkdf_label(key_label, key_label_len, key_len,
                                                            hkdf_key_label, hkdf_key_label_len);
    if (hkdf_key_label_actual_len == 0) {
        printf("ERROR building hkdf key label\n");
        return;
    }
    short hkdf_iv_label_actual_len = cuda_build_hkdf_label(iv_label, iv_label_len, iv_len,
                                                           hkdf_iv_label, hkdf_iv_label_len);
    if (hkdf_iv_label_actual_len == 0) {
        printf("ERROR building hkdf iv label\n");
        return;
    }

    cuda_hkdf_expand_sha256(d_app_traffic_secret_0, d_app_traffic_secret_len,
                            hkdf_key_label, hkdf_key_label_actual_len,
                            d_key, key_len);
    cuda_hkdf_expand_sha256(d_app_traffic_secret_0, d_app_traffic_secret_len,
                            hkdf_iv_label, hkdf_iv_label_actual_len,
                            d_iv, iv_len);
}

// This function implements the TLS 1.2 key expansion for AES-256-GCM-SHA384.
// It derives a 72-byte key block from the master secret, server random, and client random,
// then partitions it as follows:
//   client_write_key: first 32 bytes
//   server_write_key: next 32 bytes
//   client_iv: next 4 bytes
//   server_iv: next 4 bytes
__device__ void cuda_derive_tls12_keys_256(const unsigned char *d_master_secret, short master_secret_len,
                         const unsigned char d_client_random[32], const unsigned char d_server_random[32],
                         unsigned char *d_client_write_key, unsigned char *d_server_write_key,
                         unsigned char *d_client_iv, unsigned char *d_server_iv)
{
    const short key_block_len = 72;
    unsigned char key_block[72];

    // Prepare the seed: "key expansion" || server_random || client_random
    const char *label = "key expansion";
    const short label_len = 13;
    const short seed_len = label_len + 32 + 32;  // Assuming client_random and server_random are 32 bytes each
    unsigned char seed[256];  // Sufficiently large buffer
    cuda_array_copy(seed, (unsigned char*) label, label_len);
    cuda_array_copy(seed + label_len, d_server_random, 32);
    cuda_array_copy(seed + label_len + 32, d_client_random, 32);

    // Compute the key block using P_SHA384 with the master secret as the key
    cuda_p_hash_sha384(d_master_secret, master_secret_len, seed, seed_len, key_block, key_block_len);

    // Partition the key block:
    // [0..31]    -> client_write_key (32 bytes)
    // [32..63]   -> server_write_key (32 bytes)
    // [64..67]   -> client_iv (4 bytes)
    // [68..71]   -> server_iv (4 bytes)
    cuda_array_copy(d_client_write_key, key_block, 32);
    cuda_array_copy(d_server_write_key, key_block + 32, 32);
    cuda_array_copy(d_client_iv, key_block + 64, 4);
    cuda_array_copy(d_server_iv, key_block + 68, 4);
}

__device__ void cuda_build_tls12_aes_gcm_nonce(uint64_t seq_num, const unsigned char d_fixed_iv[4], unsigned char d_nonce[12]) {
    // First 4 bytes: the fixed IV
    cuda_array_copy(d_nonce, d_fixed_iv, 4);
    // Next 8 bytes: the explicit IV, which is the record sequence number in network byte order
    for (int i = 0; i < 8; i++) {
        d_nonce[4 + i] = (unsigned char)((seq_num >> (8 * i)) & 0xff);
    }
}
