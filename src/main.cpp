#include <stdio.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
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

int main() {

    std::vector<unsigned char> haystack = loadFileBytes("../resources/vm-dump.raw");

    unsigned long long h_entropy_candidates = entropy_scan(haystack.data(), haystack.size(), 48, 5.37f);

    unsigned long h_entropy_candidates_fraq = haystack.size() / h_entropy_candidates;

    double h_entropy_candidates_percent = 100.0 / h_entropy_candidates_fraq;

    printf("> Found %llu entropy candidates (%f %%)\n", h_entropy_candidates, h_entropy_candidates_percent);


    return 0;
}