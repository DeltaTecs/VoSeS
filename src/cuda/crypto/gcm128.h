
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

__device__ bool cuda_GCM_128_verify_tag(const unsigned char* d_ciphertext, int ciphertext_length, const unsigned char* d_aad, int aad_length,const  unsigned char* d_nonce, const unsigned char* d_key);
