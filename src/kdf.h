#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "hmac-sha384.h"

// This function implements the TLS 1.2 key expansion for AES-256-GCM.
// It derives a 72-byte key block from the master secret, server random, and client random,
// then partitions it as follows:
//   client_write_key: first 32 bytes
//   server_write_key: next 32 bytes
//   client_iv: next 4 bytes
//   server_iv: next 4 bytes
void derive_tls12_keys_256(const unsigned char *master_secret, size_t master_secret_len,
                         const unsigned char *client_random, const unsigned char *server_random,
                         unsigned char *client_write_key, unsigned char *server_write_key,
                         unsigned char *client_iv, unsigned char *server_iv);

// This function implements the TLS 1.2 key expansion for AES-128-GCM.
// It derives a 40-byte key block from the master secret, server random, and client random,
// then partitions it as follows:
//   client_write_key: first 16 bytes
//   server_write_key: next 16 bytes
//   client_iv: next 4 bytes
//   server_iv: next 4 bytes
void derive_tls12_keys_128(const unsigned char *master_secret, size_t master_secret_len,
                         const unsigned char *client_random, const unsigned char *server_random,
                         unsigned char *client_write_key, unsigned char *server_write_key,
                         unsigned char *client_iv, unsigned char *server_iv);


/* Build the 12-byte AES-GCM nonce for a TLS record.
 * Parameters:
 *   seq_num  - the 64-bit record sequence number
 *   fixed_iv - the 4-byte fixed IV (client_iv or server_iv)
 *   nonce    - output buffer (must be at least 12 bytes)
 */
void build_tls12_aes_gcm_nonce(uint64_t seq_num, const unsigned char fixed_iv[4], unsigned char nonce[12]);