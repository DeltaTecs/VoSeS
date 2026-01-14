cmake_minimum_required(VERSION 3.8)
project(VoSeS LANGUAGES CXX CUDA)

set(VOS_CUDA_SOURCES
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
    src/cuda/extract/extractor.cu
)

# Find and enable OpenMP
find_package(OpenMP REQUIRED)

function(voses_configure_target target)
    target_include_directories(${target} PRIVATE src)
    set_target_properties(${target} PROPERTIES CUDA_SEPARABLE_COMPILATION ON)
    if(OpenMP_CXX_FOUND)
        target_link_libraries(${target} PRIVATE OpenMP::OpenMP_CXX)
    endif()
endfunction()

add_executable(voses src/main.cpp ${VOS_CUDA_SOURCES})
voses_configure_target(voses)

add_executable(voses_tests src/test.cpp src/cuda/test.cu ${VOS_CUDA_SOURCES})
voses_configure_target(voses_tests)

enable_testing()
add_test(NAME voses_tests COMMAND $<TARGET_FILE:voses_tests>)

add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -C $<CONFIGURATION>
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Run tests"
)
add_dependencies(run_tests voses_tests)

