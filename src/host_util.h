#include <vector>

__host__ std::vector<unsigned char> hexStringToByteArray(const std::string& hex) {
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