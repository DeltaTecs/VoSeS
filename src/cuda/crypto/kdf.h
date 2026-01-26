#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// This function implements the TLS 1.2 key expansion for AES-256-GCM.
// It derives a 72-byte key block from the master secret, server random, and client random,
// then partitions it as follows:
//   d_client_write_key: first 32 bytes
//   d_server_write_key: next 32 bytes
//   d_client_iv: next 4 bytes
//   d_server_iv: next 4 bytes
__device__ void cuda_derive_tls12_keys_256(const unsigned char *d_master_secret, short d_master_secret_len,
                         const unsigned char d_client_random[32], const unsigned char d_server_random[32],
                         unsigned char *d_client_write_key, unsigned char *d_server_write_key,
                         unsigned char *d_client_iv, unsigned char *d_server_iv);

// This function implements the TLS 1.2 key expansion for AES-128-GCM.
// It derives a 40-byte key block from the master secret, server random, and client random,
// then partitions it as follows:
//   d_client_write_key: first 16 bytes
//   d_server_write_key: next 16 bytes
//   d_client_iv: next 4 bytes
//   d_server_iv: next 4 bytes
__device__ void cuda_derive_tls12_keys_128(const unsigned char *d_master_secret, short d_master_secret_len,
                         const unsigned char d_client_random[32], const unsigned char d_server_random[32],
                         unsigned char *d_client_write_key, unsigned char *d_server_write_key,
                         unsigned char *d_client_iv, unsigned char *d_server_iv);

// This function implements the TLS 1.3 key expansion for AES-128-GCM-SHA256 application traffic secrets.
// It derives a 16-byte write key and a 12-byte IV from the application traffic secret using applications of the HKDF.
//   d_key: 16 bytes
//   d_iv: 12 bytes
__device__ void cuda_derive_tls13_key_128(const unsigned char *d_app_traffic_secret_0, short d_app_traffic_secret_len,
                         unsigned char *d_key, unsigned char *d_iv);

// This function implements the TLS 1.3 key expansion for AES-256-GCM-SHA384 application traffic secrets.
// It derives a 32-byte write key and a 12-byte IV from the application traffic secret using HKDF-Expand-Label.
//   d_key: 32 bytes
//   d_iv: 12 bytes
__device__ void cuda_derive_tls13_key_256(const unsigned char *d_app_traffic_secret_0, short d_app_traffic_secret_len,
                         unsigned char *d_key, unsigned char *d_iv);

// This function implements QUIC key derivation for AES-128-GCM-SHA256.
// It derives a 16-byte key, a 12-byte IV, and a 16-byte header protection key using HKDF-Expand-Label.
//   d_key: 16 bytes
//   d_iv: 12 bytes
//   d_hp_key: 16 bytes
__device__ void cuda_derive_quic_keys_128(const unsigned char *d_secret, short d_secret_len,
                         unsigned char *d_key, unsigned char *d_iv, unsigned char *d_hp_key);

// This function implements QUIC key derivation for AES-256-GCM-SHA384.
// It derives a 32-byte key, a 12-byte IV, and a 32-byte header protection key using HKDF-Expand-Label.
//   d_key: 32 bytes
//   d_iv: 12 bytes
//   d_hp_key: 32 bytes
__device__ void cuda_derive_quic_keys_256(const unsigned char *d_secret, short d_secret_len,
                         unsigned char *d_key, unsigned char *d_iv, unsigned char *d_hp_key);

/* Build the 12-byte AES-GCM d_nonce for a TLS record.
 * Parameters:
 *   seq_num  - the 64-bit record sequence number
 *   d_fixed_iv - the 4-byte fixed IV (d_client_iv or d_server_iv)
 *   d_nonce    - output buffer (must be at least 12 bytes)
 */
__device__ void cuda_build_tls12_aes_gcm_nonce(uint64_t seq_num, const unsigned char d_fixed_iv[4], unsigned char d_nonce[12]);

// TLS 1.2 AES-GCM record uses an 8-byte explicit nonce (aka nonce_explicit) carried in the record
// fragment, concatenated to the 4-byte fixed IV derived from the key block.
__device__ void cuda_build_tls12_aes_gcm_nonce_from_explicit(const unsigned char d_explicit_nonce[8], const unsigned char d_fixed_iv[4], unsigned char d_nonce[12]);
