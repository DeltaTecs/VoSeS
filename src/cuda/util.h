static inline void array_copy(unsigned char* dst, const unsigned char* src, int length) {
    #pragma unroll
    for (int i = 0; i < length; i++) {
        dst[i] = src[i];
    }
}

static inline void array_set_zero(unsigned char* dst, int length) {
    #pragma unroll
    for (int i = 0; i < length; i++) {
        dst[i] = 0x00;
    }
}