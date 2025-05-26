cmake_minimum_required(VERSION 3.8)
project(VoSeS LANGUAGES CXX CUDA)

# Add the executable target with CUDA files
#add_executable(voses src/cuda/test.cu src/cuda/crypto/aes128.cu src/cuda/crypto/aes256.cu src/cuda/crypto/sha256.cu src/cuda/crypto/sha384.cu src/cuda/crypto/hmac-sha256.cu src/cuda/crypto/hmac-sha384.cu src/cuda/crypto/kdf.cu src/cuda/crypto/gcm128.cu src/cuda/crypto/gcm256.cu src/cuda/extract/tls-gcm-extract.cu)
add_executable(voses src/main.cpp
               src/cuda/crypto/aes128.cu
               src/cuda/crypto/aes256.cu
               src/cuda/crypto/sha256.cu
               src/cuda/crypto/sha384.cu
               src/cuda/crypto/hmac-sha256.cu
               src/cuda/crypto/hmac-sha384.cu
               src/cuda/crypto/kdf.cu
               src/cuda/crypto/gcm128.cu
               src/cuda/crypto/gcm256.cu
               src/cuda/extract/tls-gcm-extract.cu
               src/cuda/extract/extractor.cu)



# Specify include directories if needed
target_include_directories(voses PRIVATE src)

# Set CUDA properties if needed
set_target_properties(voses PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

# Find and enable OpenMP
find_package(OpenMP REQUIRED)
if(OpenMP_CXX_FOUND)
    target_link_libraries(voses PRIVATE OpenMP::OpenMP_CXX)
endif()
