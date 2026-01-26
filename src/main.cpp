#include <stdio.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <limits>
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

bool parseQuicVarInt(const unsigned char* data, size_t data_len, size_t offset,
                     uint64_t* value, size_t* consumed_len) {
    if (offset >= data_len) {
        return false;
    }
    unsigned char first = data[offset];
    size_t length = static_cast<size_t>(1u << (first >> 6));
    if (offset + length > data_len) {
        return false;
    }
    uint64_t parsed = first & 0x3f;
    for (size_t i = 1; i < length; ++i) {
        parsed = (parsed << 8) | data[offset + i];
    }
    *value = parsed;
    *consumed_len = length;
    return true;
}

bool parseQuicPacketPnOffset(const unsigned char* packet, size_t packet_len, int dcid_len_hint,
                             size_t* pn_offset_out, std::string* error_out) {
    if (packet_len == 0) {
        *error_out = "QUIC packet is empty.";
        return false;
    }

    unsigned char first = packet[0];
    bool is_long_header = (first & 0x80) != 0;
    if ((first & 0x40) == 0) {
        *error_out = "QUIC fixed bit is not set.";
        return false;
    }

    if (!is_long_header) {
        if (dcid_len_hint < 0) {
            *error_out = "Short header requires --dcid_len to compute pn_offset.";
            return false;
        }
        if (dcid_len_hint > 20) {
            *error_out = "Short header dcid_len is larger than 20 bytes.";
            return false;
        }
        size_t offset = 1 + static_cast<size_t>(dcid_len_hint);
        if (offset >= packet_len) {
            *error_out = "Short header is too short for dcid_len.";
            return false;
        }
        *pn_offset_out = offset;
        return true;
    }

    if (packet_len < 6) {
        *error_out = "Long header is too short for version field.";
        return false;
    }

    uint32_t version = (static_cast<uint32_t>(packet[1]) << 24) |
                       (static_cast<uint32_t>(packet[2]) << 16) |
                       (static_cast<uint32_t>(packet[3]) << 8) |
                       static_cast<uint32_t>(packet[4]);
    if (version == 0) {
        *error_out = "Version Negotiation packet does not include a packet number.";
        return false;
    }

    size_t pos = 5;
    if (pos >= packet_len) {
        *error_out = "Missing DCID length.";
        return false;
    }
    unsigned char dcid_len = packet[pos++];
    if (dcid_len > 20) {
        *error_out = "DCID length exceeds 20 bytes.";
        return false;
    }
    if (pos + dcid_len > packet_len) {
        *error_out = "Packet too short for DCID.";
        return false;
    }
    pos += dcid_len;

    if (pos >= packet_len) {
        *error_out = "Missing SCID length.";
        return false;
    }
    unsigned char scid_len = packet[pos++];
    if (scid_len > 20) {
        *error_out = "SCID length exceeds 20 bytes.";
        return false;
    }
    if (pos + scid_len > packet_len) {
        *error_out = "Packet too short for SCID.";
        return false;
    }
    pos += scid_len;

    unsigned char long_type = static_cast<unsigned char>((first >> 4) & 0x03);
    if (long_type == 0x03) {
        *error_out = "Retry packet does not include a packet number.";
        return false;
    }

    if (long_type == 0x00) {
        uint64_t token_len = 0;
        size_t token_len_bytes = 0;
        if (!parseQuicVarInt(packet, packet_len, pos, &token_len, &token_len_bytes)) {
            *error_out = "Failed to parse Initial token length.";
            return false;
        }
        pos += token_len_bytes;
        if (pos + token_len > packet_len) {
            *error_out = "Packet too short for Initial token.";
            return false;
        }
        pos += static_cast<size_t>(token_len);
    }

    uint64_t payload_len = 0;
    size_t payload_len_bytes = 0;
    if (!parseQuicVarInt(packet, packet_len, pos, &payload_len, &payload_len_bytes)) {
        *error_out = "Failed to parse QUIC payload length.";
        return false;
    }
    pos += payload_len_bytes;
    if (pos >= packet_len) {
        *error_out = "Packet too short for packet number.";
        return false;
    }

    *pn_offset_out = pos;
    (void)payload_len;
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
              << " --quic "
              << " --quic_packet <path> "
              << "[--dcid_len <int>] "
              << "--client_random|-cr <32-byte hex> "
              << "(--client|--server) "
              << "--algorithm|-a <gcm_256_sha_384|gcm_128_sha_256> "
              << "--haystack|-h <path>  (memory dump file path) "
              << "[--key-log <path>] "
              << "[--memory-alignment|-ma <int>] "
              << "[--entropy|-e <float>] "
              << "[--entropy-scan|-es]\n";
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
    std::string quic_packet_path;
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
    int quic_dcid_len = -1;

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
        } else if (arg == "--quic_packet") {
            if (i + 1 < argc) {
                quic_packet_path = argv[++i];
            } else {
                std::cerr << "Error: Missing value for " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        } else if (arg == "--dcid_len") {
            if (i + 1 < argc) {
                quic_dcid_len = std::stoi(argv[++i]);
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

    if (memory_alignment == 0) {
        std::cerr << "Error: --memory-alignment must be greater than zero." << std::endl;
        return 1;
    }
    if (!set_memory_alignment(memory_alignment)) {
        std::cerr << "Error: failed to set memory alignment." << std::endl;
        return 1;
    }

    bool has_app_data_record = !app_data_record_path.empty();
    bool has_quic_packet = !quic_packet_path.empty();
    bool use_tls13 = mode_tls13;
    bool use_quic = mode_quic;
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
        if (!server_random.empty() || !client_finished.empty() || has_quic_packet || quic_dcid_len >= 0) {
            std::cerr << "Error: TLS 1.3 mode does not accept TLS 1.2 or QUIC inputs." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    } else if (use_quic) {
        if (!has_quic_packet) {
            std::cerr << "Error: QUIC mode requires --quic_packet." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (!(scan_client ^ scan_server)) {
            std::cerr << "Error: QUIC mode requires --client or --server." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (client_random.empty()) {
            std::cerr << "Error: QUIC mode requires --client_random." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (algorithm.empty()) {
            std::cerr << "Error: QUIC mode requires --algorithm." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (!server_random.empty() || !client_finished.empty() || has_app_data_record || has_seq_num) {
            std::cerr << "Error: QUIC mode does not accept TLS 1.2 or TLS 1.3 inputs." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        if (quic_dcid_len > 20) {
            std::cerr << "Error: --dcid_len must be between 0 and 20." << std::endl;
            return 1;
        }
    } else {
        if (has_app_data_record || has_seq_num || has_quic_packet || quic_dcid_len >= 0) {
            std::cerr << "Error: TLS 1.2 mode does not accept TLS 1.3 or QUIC inputs." << std::endl;
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
    if (use_tls13 || use_quic) {
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

    if (!use_tls13 && !use_quic) {
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
    std::vector<unsigned char> quic_packet;
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
    } else if (use_quic) {
        try {
            printf("loading quic packet file %s ...\n", quic_packet_path.c_str());
            quic_packet = loadFileBytes(quic_packet_path);
        } catch (const std::exception& e) {
            std::cerr << "Error loading quic packet file: " << e.what() << std::endl;
            return -1;
        }
        if (quic_packet.empty()) {
            std::cerr << "Error: --quic_packet is empty." << std::endl;
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
    } else if (use_quic) {
        printf("specified quic packet length: %zu bytes\n", quic_packet.size());

        size_t pn_offset = 0;
        std::string pn_error;
        if (!parseQuicPacketPnOffset(quic_packet.data(), quic_packet.size(), quic_dcid_len, &pn_offset, &pn_error)) {
            std::cerr << "Error: failed to parse QUIC packet: " << pn_error << std::endl;
            return 1;
        }
        if (pn_offset + 4 + 16 > quic_packet.size()) {
            std::cerr << "Error: QUIC packet too short for header protection sample." << std::endl;
            return 1;
        }
        if (pn_offset > static_cast<size_t>(std::numeric_limits<short>::max())) {
            std::cerr << "Error: QUIC pn_offset is too large for CUDA kernel parameters." << std::endl;
            return 1;
        }
        if (quic_packet.size() > static_cast<size_t>(std::numeric_limits<short>::max())) {
            std::cerr << "Error: QUIC packet length is too large for CUDA kernel parameters." << std::endl;
            return 1;
        }
        short pn_offset_short = static_cast<short>(pn_offset);
        int packet_length = static_cast<int>(quic_packet.size());

        unsigned long long key_location = k_addr_not_found;
        size_t key_length = 0;
        std::string key_label;
        if (algorithm == "gcm_128_sha_256") {
            key_length = kTls13AppTrafficSecret0LenSha256;
            key_label = scan_client ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0";
            key_location = quic_app_traffic_secret_0_gcm_128_sha_256_scan(haystack.data(), haystack.size(),
                                                                           quic_packet.data(),
                                                                           packet_length, pn_offset_short,
                                                                           client_random_arr,
                                                                           entropy_threshold, scan_client);
        } else if (algorithm == "gcm_256_sha_384") {
            key_length = kTls13AppTrafficSecret0LenSha384;
            key_label = scan_client ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0";
            key_location = quic_app_traffic_secret_0_gcm_256_sha_384_scan(haystack.data(), haystack.size(),
                                                                           quic_packet.data(),
                                                                           packet_length, pn_offset_short,
                                                                           client_random_arr,
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
