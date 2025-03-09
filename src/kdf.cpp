#include "kdf.h"
#include "util.h"

// p_hash_sha384 computes the output of the TLS P_SHA384 function.
// It repeatedly computes HMAC(secret, A(i) || seed) where A(0)=seed and
// A(i) = HMAC(secret, A(i-1)). The outputs are concatenated until out_len bytes are produced.
void p_hash_sha384(const unsigned char *secret, size_t secret_len,
                   const unsigned char *seed, size_t seed_len,
                   unsigned char *out, size_t out_len)
{
    unsigned char A[48];        // A(1) initially; HMAC-SHA384 produces 48 bytes
    unsigned char hmac_buf[48];
    size_t pos = 0;
    
    // A(1) = HMAC(secret, seed)
    hmac_sha256(secret, secret_len, seed, seed_len, A);

    while (pos < out_len) {
        // Compute HMAC(secret, A(i) || seed)
        unsigned char *A_seed = (unsigned char*) malloc(48 + seed_len);
        array_copy(A_seed, A, 48);
        array_copy(A_seed + 48, seed, seed_len);
        hmac_sha256(secret, secret_len, A_seed, 48 + seed_len, hmac_buf);
        
        // Copy as many bytes as needed
        size_t bytes_to_copy = (out_len - pos < 48) ? (out_len - pos) : 48;
        array_copy(out + pos, hmac_buf, bytes_to_copy);
        pos += bytes_to_copy;
        
        // Next A = HMAC(secret, A)
        hmac_sha256(secret, secret_len, A, 48, A);
        free(A_seed);
    }
}

// p_hash_sha256 computes the output of the TLS P_SHA256 function.
// It repeatedly computes HMAC(secret, A(i) || seed) where A(0)=seed and
// A(i) = HMAC(secret, A(i-1)). The outputs are concatenated until out_len bytes are produced.
void p_hash_sha256(const unsigned char *secret, size_t secret_len,
                   const unsigned char *seed, size_t seed_len,
                   unsigned char *out, size_t out_len)
{
    unsigned char A[32];        // A(1) initially; HMAC-SHA256 produces 32 bytes
    unsigned char hmac_buf[32];
    size_t pos = 0;
    
    // A(1) = HMAC(secret, seed)
    hmac_sha256(secret, secret_len, seed, seed_len, A);

    while (pos < out_len) {
        // Allocate a buffer for A(i) || seed
        size_t A_seed_len = 32 + seed_len;
        unsigned char *A_seed = (unsigned char*) malloc(A_seed_len);
        array_copy(A_seed, A, 32);
        array_copy(A_seed + 32, seed, seed_len);

        // Compute HMAC(secret, A(i) || seed)
        hmac_sha256(secret, secret_len, A_seed, A_seed_len, hmac_buf);
        
        // Copy as many bytes as needed from the current HMAC output
        size_t bytes_to_copy = (out_len - pos < 32) ? (out_len - pos) : 32;
        array_copy(out + pos, hmac_buf, bytes_to_copy);
        pos += bytes_to_copy;
        
        // Compute next A = HMAC(secret, A)
        hmac_sha256(secret, secret_len, A, 32, A);
        free(A_seed);
    }
}

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
                              unsigned char *client_iv, unsigned char *server_iv)
{
    const size_t key_block_len = 40;
    unsigned char key_block[40];

    // Prepare the seed: "key expansion" || server_random || client_random
    const char *label = "key expansion";
    size_t label_len = strlen(label);
    size_t seed_len = label_len + 32 + 32;  // Assuming client_random and server_random are 32 bytes each
    unsigned char seed[256];  // Sufficiently large buffer
    array_copy(seed, (unsigned char*) label, label_len);
    array_copy(seed + label_len, server_random, 32);
    array_copy(seed + label_len + 32, client_random, 32);

    // Compute the key block using P_SHA256 with the master secret as the key
    p_hash_sha256(master_secret, master_secret_len, seed, seed_len, key_block, key_block_len);

    array_copy(client_write_key, key_block, 16);
    array_copy(server_write_key, key_block + 16, 16);
    array_copy(client_iv, key_block + 32, 4);
    array_copy(server_iv, key_block + 36, 4);
}

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
                         unsigned char *client_iv, unsigned char *server_iv)
{
    const size_t key_block_len = 72;
    unsigned char key_block[72];

    // Prepare the seed: "key expansion" || server_random || client_random
    const char *label = "key expansion";
    size_t label_len = strlen(label);
    size_t seed_len = label_len + 32 + 32;  // Assuming client_random and server_random are 32 bytes each
    unsigned char seed[256];  // Sufficiently large buffer
    array_copy(seed, (unsigned char*) label, label_len);
    array_copy(seed + label_len, server_random, 32);
    array_copy(seed + label_len + 32, client_random, 32);

    // Compute the key block using P_SHA384 with the master secret as the key
    p_hash_sha384(master_secret, master_secret_len, seed, seed_len, key_block, key_block_len);

    // Partition the key block:
    // [0..31]    -> client_write_key (32 bytes)
    // [32..63]   -> server_write_key (32 bytes)
    // [64..67]   -> client_iv (4 bytes)
    // [68..71]   -> server_iv (4 bytes)
    array_copy(client_write_key, key_block, 32);
    array_copy(server_write_key, key_block + 32, 32);
    array_copy(client_iv, key_block + 64, 4);
    array_copy(server_iv, key_block + 68, 4);
}

void build_tls12_aes_gcm_nonce(uint64_t seq_num, const unsigned char fixed_iv[4], unsigned char nonce[12]) {
    // First 4 bytes: the fixed IV
    array_copy(nonce, fixed_iv, 4);
    // Next 8 bytes: the explicit IV, which is the record sequence number in network byte order
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (unsigned char)((seq_num >> (56 - 8 * i)) & 0xff);
    }
}