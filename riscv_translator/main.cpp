#include <iostream>
#include <vector>
#include <fstream>
#include <capstone/capstone.h>
#include <set>

int print_header() {
	printf("#include <stdint.h>\n");
	printf("#include <stdio.h>\n");
	printf("#include <stdlib.h>\n");
	printf("#include <sys/mman.h>\n");
	printf("#include <fcntl.h>\n");
	printf("#include <unistd.h>\n");
	printf("#include <elf.h>\n\n");

	printf("// Global RV32 State\n");
	printf("int32_t x[32] = {0};\n");
	printf("uint8_t* memory = NULL;\n\n");
}

int print_init_memory() {
	printf("void init_memory(const char* elf_path) {\n");
	printf("    // Reserve the full 32-bit address space\n");
	printf("    memory = mmap(NULL, 0x100000000, PROT_READ | PROT_WRITE, \n");
	printf("                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);\n");
	printf("    if (memory == MAP_FAILED) { perror(\"mmap\"); exit(1); }\n\n");
	printf("    int fd = open(elf_path, O_RDONLY);\n");
	printf("    if (fd < 0) { perror(\"open\"); exit(1); }\n\n");
	printf("    Elf32_Ehdr ehdr;\n");
	printf("    read(fd, &ehdr, sizeof(ehdr));\n");
	printf("    Elf32_Phdr* phdrs = malloc(sizeof(Elf32_Phdr) * ehdr.e_phnum);\n");
	printf("    lseek(fd, ehdr.e_phoff, SEEK_SET);\n");
	printf("    read(fd, phdrs, sizeof(Elf32_Phdr) * ehdr.e_phnum);\n\n");
	printf("    for (int i = 0; i < ehdr.e_phnum; i++) {\n");
	printf("        if (phdrs[i].p_type == PT_LOAD) {\n");
	printf("            lseek(fd, phdrs[i].p_offset, SEEK_SET);\n");
	printf("            read(fd, &memory[phdrs[i].p_vaddr], phdrs[i].p_filesz);\n");
	printf("        }\n");
	printf("    }\n");
	printf("    free(phdrs);\n");
	printf("    close(fd);\n");
	printf("}\n");
}


int print_main() {
	printf("\nint main(int argc, char** argv) {\n");
	printf("    if (argc < 2) { printf(\"Usage: %%s <original_elf>\\n\", argv[0]); return 1; }\n");
	printf("    init_memory(argv[1]);\n");
	printf("    // The entry point will be passed to your run_cpu function\n");
	printf("    // We'll calculate this during translation\n");
	printf("    run_cpu(0x%x);\n", entry_point_value); 
	printf("    return 0;\n");
	printf("}\n");
}




//is this even necessary?
int get_reg_index(csh handle, unsigned int reg_id) {
	std::string name = cs_reg_name(handle, reg_id);
	if (name[0] == 'x') {
		return std::stoi(name.substr(1));
	}
	// Handle ABI names (a0, t1, etc.) if Capstone returns them
	// Note: In CS_MODE_RISCV64, it usually returns x0-x31i
	std::cout << "got " << name <<  ". exiting, register names should begin with x" << std::endl;
	return -1;
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
	print_main();

	while (code_size > 0) {
		bool success = cs_disasm_iter(handle, &code_ptr, &code_size, &address, insn);

		if (success) {
			translate_to_c(handle, insn);
		} else {
			if (code_size >= 4) {
				uint32_t raw_instr = *(uint32_t*)code_ptr;

				printf("    // Custom Instruction: 0x%08x\n", raw_instr);

				//advance pointers manually
				code_ptr += 4;
				code_size -= 4;
				address += 4;

			} else {
				break; //trailing jumk
			}
		}

	}

	cs_free(insn, 1);
	cs_close(&handle);
	return 0;


}


