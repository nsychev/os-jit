#include <cstring>
#include <iostream>
#include <sys/mman.h>

unsigned const char code[] = {
    0x55,                          // push  rbp
    0x48, 0x89, 0xe5,              // mov   rbp, rsp
    0xb8, 0x2a, 0x00, 0x00, 0x00,  // mov   eax, 0x2a
    0x5d,                          // pop   rbp
    0xc3                           // ret
};

const size_t size = 11;

typedef int (*func)();

int main(int argc, char** argv) {    
    void* memory = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(memory, code, size);
    mprotect(memory, size, PROT_READ | PROT_EXEC);
    func f = (func)memory;

    std::cout << f() << std::endl;

    munmap(memory, size);

    return EXIT_SUCCESS;
}
