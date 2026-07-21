#include <fstream>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    std::ifstream input;
    input.open(argv[1]);
    return input.good() ? 0 : 1;
}
