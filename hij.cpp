#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sys/mman.h>
#include <vector>

const int CALL_FAILED = -1;

using byte = unsigned char;

const std::string INT_INFO = R"(hij, version 1.3

Interactive HQ+ shell
)";

const std::string USAGE_INFO = R"(hij, version 1.3

hij is simple HQ+ JIT compiler.

USAGE

hij [-cehr] [<source>] [<binary>]

    -h                      Prints this help

    -r <source>             Compiles the program and runs it

    -c <source> <binary>    Compiles the program and saves binary file
    
    -e <binary>             Runs generated binary file (use with caution)

These options can't be combined.

When running without options, shows interactive shell.

LANGUAGE SYNTAX

HQ+ language is subscript of the famous esoteric language HQ9+.
There are three directives in HQ+ language:

    H   Prints "Hello, World!"
    Q   Prints source code of program (aka quine)
    +   Increments the accumulator

This compiler prints accumulator value when program is finished.
All other symbols in program are ignored.

DISCLAIMER

Please use this program ONLY in virtual machine or some other sandboxed
environment. Whole compiler's behaviour is undefined and it may harm your
computer at any moment. Author disclaims all warranties with regard to
this software.)";

class shellcode {
private:
    std::vector<byte> code;

public:
    shellcode(const byte bytes[], size_t len): code(bytes, bytes + len) {}

    template<size_t N>
    shellcode(std::array<byte, N> bytes): code(bytes.begin(), bytes.end()) {}
    
    shellcode& operator+=(const shellcode& other) {
        code.insert(code.end(), other.code.begin(), other.code.end());
        return *this;
    }
    
    const byte* data() const {
        return code.data();
    }

    size_t size() const {
        return code.size();
    }
};

const shellcode header(std::array<byte, 48>{
    0x55,                                            // push  rbp
    0x48, 0x89, 0xe5,                                // mov   rbp, rsp

    0x41, 0x50,                                      // push  r8
    0x49, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,        // mov   r8, 0x0
    
    0x48, 0x83, 0xec, 0x10,                          // sub   rsp, 0x10
    0xc7, 0x04, 0x24, 0x48, 0x65, 0x6c, 0x6c,        // mov   DWORD PTR [rsp], 0x48656c6c ; Hell
    0xc7, 0x44, 0x24, 0x04, 0x6f, 0x2c, 0x20, 0x77,  // mov   DWORD PTR [rsp+0x4], 0x6f2c2077 ; o, w
    0xc7, 0x44, 0x24, 0x08, 0x6f, 0x72, 0x6c, 0x64,  // mov   DWORD PTR [rsp+0x8], 0x6f726c64 ; orld
    0xc7, 0x44, 0x24, 0x0c, 0x21, 0x0a, 0x00, 0x00   // mov   DWORD PTR [rsp+0xc], 0x210a0000 ; !
});

const shellcode increment(std::array<byte, 3>{
    0x49, 0xff, 0xc0                                 // inc   r8
});

const shellcode footer(std::array<byte, 11>{
    0x4c, 0x89, 0xc0,                                // mox   rax, r8
    0x41, 0x58,                                      // pop   r8
    0x48, 0x83, 0xc4, 0x10,                          // add   rsp, 0x10
    0x5d,                                            // pop   rbp
    0xc3                                             // ret
});

typedef int (*func)();

void print_error(const char* reason) {
    std::cerr << "hij: " << reason;
    if (errno) {
        std::cerr << ": " << strerror(errno);
    }
    std::cerr << std::endl;
}

std::pair<size_t, shellcode> gen_push_quine(const char* command, size_t size) {
    ++size; // zero-byte
    while (size % 4 != 0) ++size; // padding

    size_t offset = 0x18 + size;

    byte payload[] = {
        0x48, 0x81, 0xec, 0x00, 0x00, 0x00, 0x00     // sub   rsp, 0x????????
    };

    memcpy(payload + 3, &size, 4); // copy size to payload

    shellcode q(payload, 7);

    for (size_t i = 0; i < size; i += 4) {
        byte payload[] = {
            0xc7, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            // mov DWORD PTR [rsp+0x????????], 0x????????
        };

        memcpy(payload + 3, &i, 4); // copy offset
        memcpy(payload + 7, command + i, 4); // copy command

        q += shellcode(payload, 11);
    }

    return std::make_pair(offset, q);
}

shellcode gen_pop_quine(size_t size) {
    ++size;
    while (size % 4 != 0) ++size;

    byte payload[] = {
        0x48, 0x81, 0xc4, 0x00, 0x00, 0x00, 0x00     // add   rsp, 0x????????
    };

    memcpy(payload + 3, &size, 4);

    return shellcode(payload, 7);
}

shellcode gen_print(size_t offset, size_t len) {
    long neg_offset = (-1) * offset;

    byte payload[] = {
        0x50, 0x53, 0x51, 0x52, 0x55, 0x56, 0x57, 0x41, 0x50, // push registers
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,        // mov   rax, 0x4
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,        // mov   rdi, 0x1
        0x48, 0x8d, 0xb5, 0x00, 0x00, 0x00, 0x00,        // lea   rsi, [rbp-0x????????]
        0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00,        // mov   rdx, 0x????????
        0x0f, 0x05,                                      // syscall
        0x41, 0x58, 0x5f, 0x5e, 0x5d, 0x5a, 0x59, 0x5b, 0x58  // pop registers
    };

    memcpy(payload + 26, &neg_offset, 4);
    memcpy(payload + 33, &len, 4);

    return shellcode(payload, 48);
}

shellcode generate(const char* command, size_t size) {
    shellcode s = header;

    auto [offset, q] = gen_push_quine(command, size);
    s += q;

    for (size_t i = 0; i < size; i++) {
        if (command[i] == '+') {
            s += increment;
        } else if (command[i] == 'H') {
            s += gen_print(0x18, 0x0e);
        } else if (command[i] == 'Q') {
            s += gen_print(offset, size + 1);
        }
    }

    s += gen_pop_quine(size);
    s += footer;

    return s;
}

std::pair<char*, size_t> read_file(const char* filename) {
    std::ifstream is(filename, std::ios::binary);

    is.seekg(0, std::ios::end);
    std::streamsize size = is.tellg();
    is.seekg(0, std::ios::beg);
        
    char* data = new char[size];
        
    if (!is.read(data, size)) {
        print_error("can't read input file");
        exit(EXIT_FAILURE);
    }

    is.close();

    return std::make_pair(data, size);
}

shellcode generate_from_file(const char* filename) {
    auto [data, size] = read_file(filename);
    
    shellcode s = generate(data, size);
    delete[] data;
    
    return s;
}

void execute(const shellcode& c) {
    size_t size = c.size();
    
    void* memory = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (memory == MAP_FAILED) {
        print_error("can't allocate memory");
        exit(EXIT_FAILURE);
    }

    memcpy(memory, c.data(), c.size());

    {
        int result = mprotect(memory, size, PROT_READ | PROT_EXEC);

        if (result == CALL_FAILED) {
            print_error("can't make memory executable");
            munmap(memory, size);
            exit(EXIT_FAILURE);
        }
    }
    
    func f = (func)memory;

    std::cout << f() << std::endl;

    {
        int result = munmap(memory, size);
        if (result == CALL_FAILED) {
            print_error("can't deallocate memory");
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char** argv) {
    if (argc == 1) {
        std::cerr << INT_INFO << std::endl;

        while (true) {
            std::cerr << "> ";
            std::cerr.flush();
            
            std::string command;
            std::getline(std::cin, command);

            if (!std::cin) {
                print_error("can't read command");
                return EXIT_FAILURE;
            }

            shellcode s = generate(command.c_str(), command.size());
            execute(s);
        } 
        std::cerr << USAGE_INFO << std::endl;
        return EXIT_FAILURE;
    }
    
    std::string mode(argv[1]);
    if (mode == "-h") {
        std::cerr << USAGE_INFO << std::endl;
        return EXIT_FAILURE;
    } else if (mode == "-c") {
        if (argc != 4) {
            print_error("invalid arguments for -c flag");

            return EXIT_FAILURE;
        }

        shellcode s = generate_from_file(argv[2]);

        std::ofstream os(argv[3], std::ofstream::binary);
        os.write((const char*)s.data(), s.size());
        if (!os) {
            print_error("can't write file");
        }
        os.close();
    } else if (mode == "-e") {
        if (argc != 3) {
            print_error("invalid arguments for -e flag");
            return EXIT_FAILURE;
        }

        auto [data, size] = read_file(argv[2]);

        shellcode s((const byte*)data, size);
        delete[] data;

        execute(s);
    } else if (mode == "-r") {
        if (argc != 3) {
            print_error("invalid arguments for -r flag");
            return EXIT_FAILURE;
        }

        shellcode s = generate_from_file(argv[2]);
        execute(s);
    } else {
        print_error("invalid arguments, -h for help");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
