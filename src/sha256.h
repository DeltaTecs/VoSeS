#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

__device__ void sha256(const unsigned char *input, size_t input_len, unsigned char *digest);
