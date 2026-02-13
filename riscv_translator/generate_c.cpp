#include <stdio.h>
#include <stdint.h>
#include <capstone/capstone.h>
#include <set>
#include <elf.h>
#include <string>
#include <iostream>
#include <vector>
#include <fstream>

void print_header() {
        printf("#include <stdint.h>\n");
        printf("#include <stdio.h>\n");
        printf("#include <stdlib.h>\n");
        printf("#include <sys/mman.h>\n");
        printf("#include <fcntl.h>\n");
        printf("#include <unistd.h>\n");
        printf("#include <elf.h>\n\n");

        printf("// Global RV64 State\n");
        printf("int64_t x[32] = {0};\n");
        printf("uint8_t* memory = NULL;\n");
	printf("uint64_t starting_address = 0;\n\n");
}


void print_init_memory() {
    printf("void init_memory(const char* elf_path) {\n");
    printf("    // 1. Reserve 4GB virtual address space\n");
    printf("    memory = mmap(NULL, 0x100000000, PROT_READ | PROT_WRITE, \n");
    printf("                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);\n");
    printf("    if (memory == MAP_FAILED) { perror(\"mmap failed\"); exit(1); }\n\n");

    printf("    // 2. Open the RISC-V binary\n");
    printf("    int fd = open(elf_path, O_RDONLY);\n");
    printf("    if (fd < 0) { perror(\"open failed\"); exit(1); }\n\n");

    printf("    // 3. Read and Validate the ELF Header\n");
    printf("    Elf64_Ehdr ehdr;\n");
    printf("    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {\n");
    printf("        perror(\"read ehdr failed\"); exit(1);\n");
    printf("    }\n\n");

    printf("    // Check Magic and Class\n");
    printf("    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1) {\n");
    printf("        fprintf(stderr, \"Error: '%%s' is not a valid ELF file\\n\", elf_path);\n");
    printf("        exit(1);\n");
    printf("    }\n");
    printf("    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {\n");
    printf("        fprintf(stderr, \"Error: Expected 64-bit ELF\\n\"); exit(1);\n");
    printf("    }\n\n");

    printf("    starting_address = ehdr.e_entry;\n");
    printf("    printf(\"[Loader] Entry point found: 0x%%08lx\\n\", starting_address);\n\n");

    printf("    // 4. Load Program Headers\n");
    printf("    Elf64_Phdr* phdrs = malloc(sizeof(Elf64_Phdr) * ehdr.e_phnum);\n");
    printf("    lseek(fd, ehdr.e_phoff, SEEK_SET);\n");
    printf("    read(fd, phdrs, sizeof(Elf64_Phdr) * ehdr.e_phnum);\n\n");

    printf("    // 5. Load PT_LOAD segments\n");
    printf("    for (int i = 0; i < ehdr.e_phnum; i++) {\n");
    printf("        if (phdrs[i].p_type == PT_LOAD) {\n");
    printf("            lseek(fd, phdrs[i].p_offset, SEEK_SET);\n");
    printf("            if (read(fd, &memory[phdrs[i].p_vaddr], phdrs[i].p_filesz) != phdrs[i].p_filesz) {\n");
    printf("                fprintf(stderr, \"Error loading segment %%d\\n\", i); exit(1);\n");
    printf("            }\n");
    printf("            printf(\"[Loader] Loaded segment at 0x%%08lx\\n\", phdrs[i].p_vaddr);\n");
    printf("        }\n");
    printf("    }\n");
    printf("    free(phdrs);\n");
    printf("    close(fd);\n");
    printf("}\n");
}


void print_main() {
        printf("\nint main(int argc, char** argv) {\n");
        printf("    if (argc < 2) { printf(\"Usage: %%s <original_elf>\\n\", argv[0]); return 1; }\n");
        printf("    init_memory(argv[1]);\n");
        printf("    // The entry point will be passed to your run_cpu function\n");
        printf("    // We'll calculate this during translation\n");
        printf("    run_cpu(starting_address);\n");
        printf("    return 0;\n");
        printf("}\n");
}


void translate_to_c(csh handle, cs_insn *insn) {
        cs_riscv *riscv = &(insn->detail->riscv);

        printf("    // %s %s\n", insn->mnemonic, insn->op_str);
}


int main(int argc, char** argv) {
        if (argc < 2) {
                std::cerr << "Usage: ./translator <riscv_binary_file>" << std::endl;
                return 1;
        }

        //read in binary
        std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
        if (!file) {
                std::cerr << "Error: Could not open file " << argv[1] << std::endl;
                return 1;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                std::cerr << "Error: Could not read file data." << std::endl;
                return 1;
        }

        //capstone init
        csh handle;
        if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle) != CS_ERR_OK) {
                std::cerr << "Error: Couldnt init capstone." << std::endl;
                return -1;
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);

        //dissasemble binary
        const uint8_t *code_ptr = buffer.data();
        size_t code_size = buffer.size();
        uint64_t address = 0x1000; //starting address????
        cs_insn *insn = cs_malloc(handle);

        print_header();
        print_init_memory();
	
	printf("void run_cpu(uint64_t entry_point) {\n");
	printf("    printf(\"%%lx\\n\", entry_point);\n");
        while (code_size > 0) {
                bool success = cs_disasm_iter(handle, &code_ptr, &code_size, &address, insn);

                if (success) {
                        translate_to_c(handle, insn);
                } else {
                        if (code_size >= 4) {
                                uint64_t raw_instr = *(uint64_t*)code_ptr;

                                printf("    // Custom Instruction: 0x%08lx\n", raw_instr);

                                //advance pointers manually
                                code_ptr += 4;
                                code_size -= 4;
                                address += 4;

                        } else {
                                break; //trailing jumk
                        }
                }

        }
	printf("}\n");

        print_main();
        cs_free(insn, 1);
        cs_close(&handle);
        return 0;


}

