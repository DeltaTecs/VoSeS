// usind https://github.com/kokke/tiny-AES-c here

#include <stdint.h>
#include <stddef.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif

#define AES128 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#define AES128_KEYLEN 16   // Key length in bytes
#define AES128_keyExpSize 176

struct AES128_ctx
{
  uint8_t RoundKey[AES128_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t Iv[AES_BLOCKLEN];
#endif
};

__device__ void cuda_AES128_init_ctx(struct AES128_ctx* ctx, const uint8_t* key);
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
__device__ void cuda_AES128_init_ctx_iv(struct AES128_ctx* ctx, const uint8_t* key, const uint8_t* iv);
__device__ void cuda_AES128_ctx_set_iv(struct AES128_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
// buffer size is exactly AES_BLOCKLEN bytes; 
// you need only AES_init_ctx as IV is not used in ECB 
// NB: ECB is considered insecure for most uses
__device__ void cuda_AES128_ECB_encrypt(const struct AES128_ctx* ctx, uint8_t* buf);
__device__ void cuda_AES128_ECB_decrypt(const struct AES128_ctx* ctx, uint8_t* buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
__device__ void cuda_AES128_CBC_encrypt_buffer(struct AES128_ctx* ctx, uint8_t* buf, size_t length);
__device__ void cuda_AES128_CBC_decrypt_buffer(struct AES128_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
__device__ void cuda_AES128_CTR_xcrypt_buffer(struct AES128_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CTR) && (CTR == 1)