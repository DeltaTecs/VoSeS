#include <stdio.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cuda_runtime.h>
#include "host_util.h"
#include "cuda/extract/extractor.h"


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

void scan_entropy(float threshold, std::vector<unsigned char> haystack) {

    unsigned long long h_entropy_candidates = entropy_scan(haystack.data(), haystack.size(), 48, threshold);
    unsigned long h_entropy_candidates_fraq = haystack.size() / h_entropy_candidates;
    double h_entropy_candidates_percent = 100.0 / h_entropy_candidates_fraq;
    printf("> Found %llu entropy candidates (%f %%)\n", h_entropy_candidates, h_entropy_candidates_percent);
}

int main() {

    const float entropy_threshold = 5.0f;

    std::vector<unsigned char> haystack = loadFileBytes("../resources/vm-dump2.raw");

    //std::string client_random = "0ba3746e1d0972175c645e563cef8341a9b3b2e8cbec214e11844ac0a69a6966";
    //std::string server_random = "c98c71e2fa221d00a47237c00c8218ecc45c5e39dc38de02067b1ebb1b82363b";
    //std::string client_finished = "16030300280000000000000000ff70e3ef3816eb9b7f32a1223938ede383600b1f188be8920a63c27045fbfc75";
    std::string client_random = "f94674af4c20c163152b9bac96bae98893445e8c248ec2394993109298ba1de4";
    std::string server_random = "624f160906742aed402906a31782ca71f4372982dde7742f38489c3f21f91a8e";
    std::string client_finished = "16030300280000000000000000cc10149018da2ba4e559782298619e2722346e7b635169e92eb832412a5346f8";
    std::vector<unsigned char> client_random_bytes = hexStringToByteArray(client_random);
    std::vector<unsigned char> server_random_bytes = hexStringToByteArray(server_random);
    std::vector<unsigned char> client_finished_bytes = hexStringToByteArray(client_finished);

    unsigned char client_random_arr[32];
    unsigned char server_random_arr[32];
    memcpy(client_random_arr, client_random_bytes.data(), 32);
    memcpy(server_random_arr, server_random_bytes.data(), 32);

    //scan_entropy(entropy_threshold, haystack);

    //tls_master_secret_gcm_128_sha_256_scan(haystack.data(), haystack.size(), client_random_arr, server_random_arr, 
    //                                       client_finished_bytes.data(), client_finished_bytes.size(), entropy_threshold);
    tls_master_secret_gcm_256_sha_384_scan(haystack.data(), haystack.size(), client_random_arr, server_random_arr, 
                                           client_finished_bytes.data(), client_finished_bytes.size(), entropy_threshold);




    return 0;
}