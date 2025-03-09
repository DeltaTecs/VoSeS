#include <stdio.h>
#include "cuda.h"
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include "gcm128.h"
#include "sha384.h"
#include "sha256.h"
#include "hmac-sha384.h"
#include "hmac-sha256.h"
#include "kdf.h"



std::vector<unsigned char> hexStringToByteArray(const std::string& hex) {
    std::vector<unsigned char> byteArray;
    
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even length");
    }
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        byteArray.push_back(byte);
    }
    
    return byteArray;
}

std::string byteArrayToHexString(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}


std::vector<unsigned char> loadFileBytes(const std::string& filename) {
    // Open the file in binary mode and set the position at the end
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    
    // Get the file size from the current position
    std::streamsize fileSize = file.tellg();
    std::vector<unsigned char> buffer(fileSize);
    
    // Return to the beginning of the file
    file.seekg(0, std::ios::beg);
    
    // Read the entire file into the vector
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        throw std::runtime_error("Failed to read file: " + filename);
    }
    
    return buffer;
}

int main() {

    std::string master_secret = "afabc92e6ac6a0a785b6518c5bef8e1010d5ec2c95e8829cd769387e8840d73dfbd0e17f4c9bdddacdc61fef992b3c06";
    std::string client_random = "0ba3746e1d0972175c645e563cef8341a9b3b2e8cbec214e11844ac0a69a6966";
    std::string server_random = "c98c71e2fa221d00a47237c00c8218ecc45c5e39dc38de02067b1ebb1b82363b";
    std::string client_finished = "16030300280000000000000000ff70e3ef3816eb9b7f32a1223938ede383600b1f188be8920a63c27045fbfc75";
    std::vector<unsigned char> master_secret_bytes = hexStringToByteArray(master_secret);
    std::vector<unsigned char> client_random_bytes = hexStringToByteArray(client_random);
    std::vector<unsigned char> server_random_bytes = hexStringToByteArray(server_random);
    std::vector<unsigned char> client_finished_bytes = hexStringToByteArray(client_finished);

    const int AES_KEY_LENGTH = 128 / 8; 
    const int AAD_LENGTH = 13;

    unsigned char client_write_key[AES_KEY_LENGTH];
    unsigned char server_write_key[AES_KEY_LENGTH];
    unsigned char client_iv[4];
    unsigned char server_iv[4];

    derive_tls12_keys_128(master_secret_bytes.data(), master_secret_bytes.size(),
                        client_random_bytes.data(), server_random_bytes.data(),
                        client_write_key, server_write_key,
                        client_iv, server_iv);

                        
    // create nonce and extract sequence number from tls payload
    unsigned char client_nonce[12] = {0};
    uint64_t target_seq_num = 0;
    memcpy(&target_seq_num, client_finished_bytes.data() + 5, 8);
    build_tls12_aes_gcm_nonce(target_seq_num, client_iv, client_nonce);

    // extract cipher text
    const int ciphertext_len = client_finished_bytes.size() - AAD_LENGTH;
    unsigned char* ciphertext_bytes = (unsigned char*) malloc(ciphertext_len);
    memcpy(ciphertext_bytes, client_finished_bytes.data() + AAD_LENGTH, ciphertext_len);

    // setup associated data
    unsigned char* aad_bytes = (unsigned char*) malloc(AAD_LENGTH);
    memcpy(aad_bytes, &target_seq_num, 8);
    aad_bytes[ 8] = 0x16; // type handshake
    aad_bytes[9] = 0x03; // version tls 1.2
    aad_bytes[10] = 0x03; // version tls 1.2
    aad_bytes[11] = 0x00; // encode length of encrypted finished message (always 12 bytes -> 16 bytes when padded)
    aad_bytes[12] = 0x10; // encode length of encrypted finished message (always 12 bytes -> 16 bytes when padded)
    uint16_t tls_compressed_len = ciphertext_len - 16;
    memcpy(aad_bytes + 12, &tls_compressed_len, 2);

    // Call the verification function.
    bool valid = GCM_128_verify_tag(ciphertext_bytes, ciphertext_len,
                                    aad_bytes, AAD_LENGTH,
                                    client_nonce, client_write_key);
    std::cout << "tag valid: "        << valid        << std::endl;
    if (valid) {
        printf("VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALLLLLLLLLLLLLLLLLLLLIIIIIIIIIIIIIIIIIIDDDDDDDDDDDDDDDDDDDDDDD\n");
        printf("VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALLLLLLLLLLLLLLLLLLLLIIIIIIIIIIIIIIIIIIDDDDDDDDDDDDDDDDDDDDDDD\n");
        printf("VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALLLLLLLLLLLLLLLLLLLLIIIIIIIIIIIIIIIIIIDDDDDDDDDDDDDDDDDDDDDDD\n");
        printf("VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALLLLLLLLLLLLLLLLLLLLIIIIIIIIIIIIIIIIIIDDDDDDDDDDDDDDDDDDDDDDD\n");
        printf("VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALLLLLLLLLLLLLLLLLLLLIIIIIIIIIIIIIIIIIIDDDDDDDDDDDDDDDDDDDDDDD\n");
        printf("VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALLLLLLLLLLLLLLLLLLLLIIIIIIIIIIIIIIIIIIDDDDDDDDDDDDDDDDDDDDDDD\n");
        printf("VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALLLLLLLLLLLLLLLLLLLLIIIIIIIIIIIIIIIIIIDDDDDDDDDDDDDDDDDDDDDDD\n");
    }
    
    return 0;
}