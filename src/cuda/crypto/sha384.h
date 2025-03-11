#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <cuda_runtime.h>

__device__ void cuda_sha384(const unsigned char *d_input, size_t input_len, unsigned char *d_digest);

