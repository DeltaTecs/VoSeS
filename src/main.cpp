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

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName
              << " --client_random|-cr <32-byte hex> "
              << "--server_random|-sr <32-byte hex> "
              << "--client_finished|-cf <hex, max 61 bytes> "
              << "--algorithm|-a <gcm_256_sha_384|gcm_128_sha_256> "
              << "--haystack|-h <path>  (memory dump file path)"
              << "[--entropy|-e <float>] "
              << "[--entropy-scan|-es]" << std::endl;
}

int main(int argc, char* argv[]) {
    // Variables to store command-line parameters.
    std::string client_random;
    std::string server_random;
    std::string client_finished;
    std::string algorithm;
    std::string haystack_path;
    float entropy_threshold = 5.0f; // Default entropy threshold.
    bool run_entropy_scan = false;

    // Parse command-line arguments.
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--client_random" || arg == "-cr") {
            if (i + 1 < argc) {
                client_random = argv[++i];
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--server_random" || arg == "-sr") {
            if (i + 1 < argc) {
                server_random = argv[++i];
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--client_finished" || arg == "-cf") {
            if (i + 1 < argc) {
                client_finished = argv[++i];
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--algorithm" || arg == "-a") {
            if (i + 1 < argc) {
                algorithm = argv[++i];
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--haystack" || arg == "-h") {
            if (i + 1 < argc) {
                haystack_path = argv[++i];
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--entropy" || arg == "-e") {
            if (i + 1 < argc) {
                entropy_threshold = std::stof(argv[++i]);
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--entropy-scan" || arg == "-es") {
            run_entropy_scan = true;
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments.
    if (client_random.empty() || server_random.empty() || client_finished.empty() ||
        algorithm.empty() || haystack_path.empty()) {
        std::cerr << "Error: Missing required arguments." << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    // Validate hex string lengths.
    if (client_random.length() != 64) { // 32 bytes = 64 hex characters.
        std::cerr << "Error: --client_random must be 32-byte hex (64 hex characters)." << std::endl;
        return 1;
    }
    if (server_random.length() != 64) {
        std::cerr << "Error: --server_random must be 32-byte hex (64 hex characters)." << std::endl;
        return 1;
    }
    // Ensure client_finished does not exceed 61 bytes (122 hex characters).
    if (client_finished.length() > 122) {
        std::cerr << "Error: --client_finished must be a hex string with a maximum of 61 bytes (122 hex characters)." << std::endl;
        return 1;
    }

    // Load the haystack file.
    std::vector<unsigned char> haystack;
    try {
        haystack = loadFileBytes(haystack_path);
    } catch (const std::exception& e) {
        std::cerr << "Error loading haystack file: " << e.what() << std::endl;
        return -1;
    }
    // Convert hex strings to byte arrays.
    std::vector<unsigned char> client_random_bytes = hexStringToByteArray(client_random);
    std::vector<unsigned char> server_random_bytes = hexStringToByteArray(server_random);
    std::vector<unsigned char> client_finished_bytes = hexStringToByteArray(client_finished);

    // Ensure that the client and server random arrays are correctly sized.
    if (client_random_bytes.size() != 32 || server_random_bytes.size() != 32) {
        std::cerr << "Error: Invalid hex value provided for client_random or server_random. Not 32 bytes." << std::endl;
        return 1;
    }
    unsigned char client_random_arr[32];
    unsigned char server_random_arr[32];
    memcpy(client_random_arr, client_random_bytes.data(), 32);
    memcpy(server_random_arr, server_random_bytes.data(), 32);

    // If the entropy-scan flag is set, run scan_entropy before other scans.
    if (run_entropy_scan) {
        scan_entropy(entropy_threshold, haystack);
    }

    printf("specified haystack file path: %s\n", haystack_path.c_str());
    printf("specified client random: ");
    for (char i = 0; i < 32; i++) {
        printf("%02x", client_random_arr[i]);
    }
    printf("\n");
    printf("specified server random: ");
    for (char i = 0; i < 32; i++) {
        printf("%02x", server_random_arr[i]);
    }
    printf("\n");
    printf("specified client finished message: ");
    for (char i = 0; i < client_finished_bytes.size(); i++) {
        printf("%02x", client_finished_bytes.data()[i]);
    }
    printf("\n");
    printf("specified algorithm: %s\n", algorithm.c_str());

    // Select and run the appropriate TLS scan based on the algorithm parameter.
    if (algorithm == "gcm_256_sha_384") {
        tls_master_secret_gcm_256_sha_384_scan(haystack.data(), haystack.size(), client_random_arr, server_random_arr,
                                               client_finished_bytes.data(), client_finished_bytes.size(), entropy_threshold);
    } else if (algorithm == "gcm_128_sha_256") {
        tls_master_secret_gcm_128_sha_256_scan(haystack.data(), haystack.size(), client_random_arr, server_random_arr,
                                               client_finished_bytes.data(), client_finished_bytes.size(), entropy_threshold);
    } else {
        std::cerr << "Error: Unsupported algorithm. Use 'gcm_256_sha_384' or 'gcm_128_sha_256'." << std::endl;
        return 1;
    }

    return 0;
}

/*
int main() {

    const float entropy_threshold = 5.0f;

    std::vector<unsigned char> haystack = loadFileBytes("../resources/vm-dump_dtls.raw");

    std::string client_random = "8da2f8cbda6886eda6070cdb7a38deb3905e3eea1c278222e2432160476d72d7";
    std::string server_random = "67d1c6448467d6310021ac7f50e0c0d0c3ebc67d2f5ae9808a185fa24d5ddd09";
    std::string client_finished = "16fefd000100000000000000300001000000000000038c9f9b705edb159414da366ef283310ecbaa50b41632b67910f271a57d6e37e418bdcb74c3feaf";

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
}*/