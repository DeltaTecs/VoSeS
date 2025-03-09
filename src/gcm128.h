
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "aes.h"
#include "util.h"

bool GCM_128_verify_tag(const unsigned char* ciphertext, int ciphertext_length, const unsigned char* aad, int aad_length,const  unsigned char* nonce, const unsigned char* key);
