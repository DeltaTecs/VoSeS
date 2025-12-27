#include "cuda/test.h"
#include <iostream>

int main() {
    std::cout << "Running tests..." << std::endl;
    if (run_tests()) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests failed." << std::endl;
        return 1;
    }
}
