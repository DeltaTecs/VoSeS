#include <stdio.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cuda_runtime.h>
#include <cstdint>
#include <cstring>
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

constexpr size_t kTls12MasterSecretLen = 48;
constexpr size_t kTls13AppTrafficSecret0LenSha256 = 32;
constexpr size_t kTls13AppTrafficSecret0LenSha384 = 48;

std::string bytesToHex(const unsigned char* bytes, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::nouppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

bool appendKeyLogLine(const std::string& path, const std::string& label,
                      const unsigned char* client_random, size_t client_random_len,
                      const unsigned char* secret, size_t secret_len) {
    std::ofstream out(path, std::ios::app);
    if (!out) {
        std::cerr << "Error: Failed to open key log file: " << path << std::endl;
        return false;
    }
    out << label << " " << bytesToHex(client_random, client_random_len) << " "
        << bytesToHex(secret, secret_len) << "\n";
    if (!out) {
        std::cerr << "Error: Failed to write key log file: " << path << std::endl;
        return false;
    }
    return true;
}

void scan_entropy(float threshold, std::vector<unsigned char> haystack) {

    unsigned long long h_entropy_candidates = entropy_scan(haystack.data(), haystack.size(), 48, threshold);
    unsigned long h_entropy_candidates_fraq = haystack.size() / h_entropy_candidates;
    double h_entropy_candidates_percent = 100.0 / h_entropy_candidates_fraq;
    printf("> Found %llu entropy candidates (%f %%)\n", h_entropy_candidates, h_entropy_candidates_percent);
}

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName
              << " --tls12 "
              << " --client_random|-cr <32-byte hex> "
              << "--server_random|-sr <32-byte hex> "
              << "--client_finished|-cf <hex, max 61 bytes> "
              << "--algorithm|-a <gcm_256_sha_384|gcm_128_sha_256> "
              << "--haystack|-h <path>  (memory dump file path) "
              << "[--key-log <path>] "
              << "[--memory-alignment|-ma <int>] "
              << "[--entropy|-e <float>] "
              << "[--entropy-scan|-es]\n"
              << "       " << progName
              << " --tls13 "
              << " --app_data_record <path> --seq_num <int> "
              << "--client_random|-cr <32-byte hex> "
              << "(--client|--server) "
              << "--algorithm|-a <gcm_256_sha_384|gcm_128_sha_256> "
              << "--haystack|-h <path>  (memory dump file path) "
              << "[--key-log <path>] "
              << "[--memory-alignment|-ma <int>] "
              << "[--entropy|-e <float>] "
              << "[--entropy-scan|-es]\n"
              << "       " << progName
              << " --quic  (not implemented yet)" << std::endl;
}

int main(int argc, char* argv[]) {
    // Variables to store command-line parameters.
    std::string client_random;
    std::string server_random;
    std::string client_finished;
    std::string algorithm;
    std::string haystack_path;
    std::string key_log_path;
    std::string app_data_record_path;
    uint64_t seq_num = 0;
    bool has_seq_num = false;
    bool scan_client = false;
    bool scan_server = false;
    float entropy_threshold = 4.4f; // Default entropy threshold.
    uint64_t memory_alignment = 4;
    bool run_entropy_scan = false;
    bool mode_tls12 = false;
    bool mode_tls13 = false;
    bool mode_quic = false;

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
        } else if (arg == "--key-log") {
            if (i + 1 < argc) {
                key_log_path = argv[++i];
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
        } else if (arg == "--memory-alignment" || arg == "-ma") {
            if (i + 1 < argc) {
                memory_alignment = std::stoull(argv[++i]);
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--app_data_record") {
            if (i + 1 < argc) {
                app_data_record_path = argv[++i];
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--seq_num") {
            if (i + 1 < argc) {
                seq_num = std::stoull(argv[++i]);
                has_seq_num = true;
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--client") {
            scan_client = true;
        } else if (arg == "--server") {
            scan_server = true;
        } else if (arg == "--tls12") {
            mode_tls12 = true;
        } else if (arg == "--tls13") {
            mode_tls13 = true;
        } else if (arg == "--quic") {
            mode_quic = true;
        } else if (arg == "--entropy-scan" || arg == "-es") {
            run_entropy_scan = true;
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    int mode_count = (mode_tls12 ? 1 : 0) + (mode_tls13 ? 1 : 0) + (mode_quic ? 1 : 0);
    if (mode_count == 0) {
        std::cerr << "Error: Missing mode flag. Use one of --tls12, --tls13, or --quic." << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    if (mode_count > 1) {
        std::cerr << "Error: --tls12, --tls13, and --quic are mutually exclusive." << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    if (mode_quic) {
        std::cerr << "Error: QUIC mode is not implemented yet." << std::endl;
        return 1;
    }

    if (memory_alignment == 0) {
        std::cerr << "Error: --memory-alignment must be greater than zero." << std::endl;
        return 1;
    }
    if (!set_memory_alignment(memory_alignment)) {
        std::cerr << "Error: failed to set memory alignment." << std::endl;
        return 1;
    }

    bool has_app_data_record = !app_data_record_path.empty();
    bool use_tls13 = mode_tls13;
    if (use_tls13) {
        if (!has_app_data_record || !has_seq_num) {
            std::cerr << "Error: TLS 1.3 mode requires --app_data_record and --seq_num." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (!(scan_client ^ scan_server)) {
            std::cerr << "Error: TLS 1.3 mode requires --client or --server." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (client_random.empty()) {
            std::cerr << "Error: TLS 1.3 mode requires --client_random." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (algorithm.empty()) {
            std::cerr << "Error: TLS 1.3 mode requires --algorithm." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (!server_random.empty() || !client_finished.empty()) {
            std::cerr << "Error: TLS 1.3 mode does not accept --server_random or --client_finished." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    } else {
        if (has_app_data_record || has_seq_num) {
            std::cerr << "Error: TLS 1.2 mode does not accept --app_data_record or --seq_num." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (scan_client || scan_server) {
            std::cerr << "Error: TLS 1.2 mode does not accept --client or --server." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments.
    if (use_tls13) {
        if (haystack_path.empty()) {
            std::cerr << "Error: Missing required arguments." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    } else {
        if (client_random.empty() || server_random.empty() || client_finished.empty() ||
            algorithm.empty() || haystack_path.empty()) {
            std::cerr << "Error: Missing required arguments." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    if (!use_tls13) {
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
    }

    // Load the haystack file.
    std::vector<unsigned char> haystack;
    try {
        printf("loading haystack file %s ...\n", haystack_path.c_str());
        haystack = loadFileBytes(haystack_path);
    } catch (const std::exception& e) {
        std::cerr << "Error loading haystack file: " << e.what() << std::endl;
        return -1;
    }
    std::vector<unsigned char> app_data_record;
    if (use_tls13) {
        try {
            printf("loading app data record file %s ...\n", app_data_record_path.c_str());
            app_data_record = loadFileBytes(app_data_record_path);
        } catch (const std::exception& e) {
            std::cerr << "Error loading app data record file: " << e.what() << std::endl;
            return -1;
        }
        if (app_data_record.empty()) {
            std::cerr << "Error: --app_data_record is empty." << std::endl;
            return 1;
        }
        if (app_data_record[0] != 0x17) {
            std::cerr << "Error: --app_data_record must start with 0x17 (TLS application data)." << std::endl;
            return 1;
        }
    }
    // If the entropy-scan flag is set, run scan_entropy before other scans.
    if (run_entropy_scan) {
        scan_entropy(entropy_threshold, haystack);
    }


    // Convert hex strings to byte arrays.
    std::vector<unsigned char> client_random_bytes = hexStringToByteArray(client_random);
    if (client_random_bytes.size() != 32) {
        std::cerr << "Error: --client_random must be 32-byte hex (64 hex characters)." << std::endl;
        return 1;
    }
    unsigned char client_random_arr[32];
    memcpy(client_random_arr, client_random_bytes.data(), 32);

    printf("specified client random: ");
    for (char i = 0; i < 32; i++) {
        printf("%02x", client_random_arr[i]);
    }
    printf("\n");

    printf("specified haystack file path: %s\n", haystack_path.c_str());
    printf("specified memory alignment: %llu bytes\n", static_cast<unsigned long long>(memory_alignment));
    if (use_tls13) {
        printf("specified app data record length: %zu bytes\n", app_data_record.size());
        printf("specified seq num: %llu\n", static_cast<unsigned long long>(seq_num));

        unsigned long long key_location = k_addr_not_found;
        size_t key_length = 0;
        std::string key_label;
        if (algorithm == "gcm_128_sha_256") {
            key_length = kTls13AppTrafficSecret0LenSha256;
            key_label = scan_client ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0";
            key_location = tls_app_traffic_secret_0_gcm_128_sha_256_scan(haystack.data(), haystack.size(),
                                                                         app_data_record.data(),
                                                                         static_cast<int>(app_data_record.size()),
                                                                         seq_num, client_random_arr,
                                                                         entropy_threshold, scan_client);
        } else if (algorithm == "gcm_256_sha_384") {
            key_length = kTls13AppTrafficSecret0LenSha384;
            key_label = scan_client ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0";
            key_location = tls_app_traffic_secret_0_gcm_256_sha_384_scan(haystack.data(), haystack.size(),
                                                                         app_data_record.data(),
                                                                         static_cast<int>(app_data_record.size()),
                                                                         seq_num, client_random_arr,
                                                                         entropy_threshold, scan_client);
        } else {
            std::cerr << "Error: Unsupported algorithm. Use 'gcm_256_sha_384' or 'gcm_128_sha_256'." << std::endl;
            return 1;
        }

        if (!key_log_path.empty() && key_length > 0 && key_location != k_addr_not_found) {
            size_t key_offset = static_cast<size_t>(key_location);
            if (key_offset + key_length > haystack.size()) {
                std::cerr << "Error: Key location is out of bounds for the haystack." << std::endl;
                return 1;
            }
            if (!appendKeyLogLine(key_log_path, key_label, client_random_arr, 32,
                                  haystack.data() + key_offset, key_length)) {
                return 1;
            }
        }
    } else {
        std::vector<unsigned char> server_random_bytes = hexStringToByteArray(server_random);
        std::vector<unsigned char> client_finished_bytes = hexStringToByteArray(client_finished);
        if (server_random_bytes.size() != 32) {
            std::cerr << "Error: --server_random must be 32-byte hex (64 hex characters)." << std::endl;
            return 1;
        }
        unsigned char server_random_arr[32];
        memcpy(server_random_arr, server_random_bytes.data(), 32);
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
        unsigned long long key_location = k_addr_not_found;
        size_t key_length = kTls12MasterSecretLen;
        std::string key_label = "CLIENT_RANDOM";
        if (algorithm == "gcm_256_sha_384") {
            key_location = tls12_master_secret_gcm_256_sha_384_scan(haystack.data(), haystack.size(), client_random_arr, server_random_arr,
                                                                    client_finished_bytes.data(), client_finished_bytes.size(), entropy_threshold);
        } else if (algorithm == "gcm_128_sha_256") {
            key_location = tls12_master_secret_gcm_128_sha_256_scan(haystack.data(), haystack.size(), client_random_arr, server_random_arr,
                                                                    client_finished_bytes.data(), client_finished_bytes.size(), entropy_threshold);
        } else {
            std::cerr << "Error: Unsupported algorithm. Use 'gcm_256_sha_384' or 'gcm_128_sha_256'." << std::endl;
            return 1;
        }

        if (!key_log_path.empty() && key_location != k_addr_not_found) {
            size_t key_offset = static_cast<size_t>(key_location);
            if (key_offset + key_length > haystack.size()) {
                std::cerr << "Error: Key location is out of bounds for the haystack." << std::endl;
                return 1;
            }
            if (!appendKeyLogLine(key_log_path, key_label, client_random_arr, 32,
                                  haystack.data() + key_offset, key_length)) {
                return 1;
            }
        }
    }

    return 0;
}
