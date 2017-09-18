#include <cstdio>
#include <string>
#include <vector>

int main(int argc, char **argv)
{
    std::vector<std::string> vector;
    vector.emplace_back("a");
    vector.emplace_back("b");
    printf("%lu\n", vector.size());
    printf("0: %s\n", vector[0].c_str());

    return 0;
}
