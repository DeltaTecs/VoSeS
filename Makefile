# Compiler settings
NVCC := nvcc
CXX := g++

# Target executable
TARGET := voses
TEST_TARGET := run_tests

# Directories
SRC_DIR := src
OBJ_DIR := obj

# Source files
CPP_SRCS := src/main.cpp
TEST_CPP_SRCS := src/test.cpp

CU_SRCS := src/cuda/crypto/aes128.cu \
           src/cuda/crypto/aes256.cu \
           src/cuda/crypto/sha256.cu \
           src/cuda/crypto/sha384.cu \
           src/cuda/crypto/hmac-sha256.cu \
           src/cuda/crypto/hmac-sha384.cu \
           src/cuda/crypto/kdf.cu \
           src/cuda/crypto/gcm128.cu \
           src/cuda/crypto/gcm256.cu \
           src/cuda/extract/tls-gcm-extract.cu \
           src/cuda/extract/extractor.cu

TEST_CU_SRCS := src/cuda/test.cu

# Object files
CPP_OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(CPP_SRCS))
CU_OBJS := $(patsubst $(SRC_DIR)/%.cu,$(OBJ_DIR)/%.o,$(CU_SRCS))
OBJS := $(CPP_OBJS) $(CU_OBJS)

TEST_CPP_OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(TEST_CPP_SRCS))
TEST_CU_OBJS := $(patsubst $(SRC_DIR)/%.cu,$(OBJ_DIR)/%.o,$(TEST_CU_SRCS))
TEST_OBJS := $(TEST_CPP_OBJS) $(TEST_CU_OBJS) $(CU_OBJS)

# Flags
INCLUDES := -Isrc
# Enable separable compilation (-rdc=true) as per CMake config
# Enable OpenMP
NVCCFLAGS := -rdc=true $(INCLUDES) -Xcompiler -fopenmp -O3
CXXFLAGS := $(INCLUDES) -fopenmp -O3
LDFLAGS := -lgomp

# Rules
all: $(TARGET)

$(TARGET): $(OBJS)
	$(NVCC) $(NVCCFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJS)
	$(NVCC) $(NVCCFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cu
	@mkdir -p $(dir $@)
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(TEST_TARGET)

.PHONY: all clean test
