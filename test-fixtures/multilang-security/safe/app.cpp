#include <fstream>

int main(void) {
    std::ifstream input;
    input.open("/etc/hosts");
    return input.good() ? 0 : 1;
}
