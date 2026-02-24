#include <stdio.h>
#include <stdint.h>
#include <capstone/capstone.h>
#include <set>
#include <elf.h>
#include <string>
#include <iostream>
#include <vector>
#include <fstream>
#include <fcntl.h>    
#include <unistd.h>
#include <sys/stat.h>

//print the C header for the stuff we need to run
void print_header() {
        printf("#include <stdint.h>\n");
        printf("#include <stdio.h>\n");
        printf("#include <stdlib.h>\n");
        printf("#include <sys/mman.h>\n");
        printf("#include <fcntl.h>\n");
        printf("#include <unistd.h>\n");
        printf("#include <elf.h>\n\n");

        printf("// Global RV64 State\n");
	
	//register file is a union so we can access registers
	//with their name or their offset in the registerfile array
	printf("typedef union {\n");
	printf("    struct {\n");
	printf("        int64_t zero, ra, sp, gp, tp, t0, t1, t2;\n");
	printf("	int64_t s0, s1, a0, a1, a2, a3, a4, a5;\n");
	printf("	int64_t a6, a7, s2, s3, s4, s5, s6, s7;\n");
	printf("	int64_t s8, s9, s10, s11, t3, t4, t5, t6;\n");
	printf("    };\n");
	printf("    int64_t regs[32];\n\n");
	printf("} RegisterFile;\n\n");

	//create variables for the memory pointer and the program entry point
        printf("uint8_t* memory = NULL;\n");
}



void translate_to_c(csh handle, cs_insn *insn) {
	printf("L_0x%ld:\n", insn->address);

        printf("    // %s %s\n", insn->mnemonic, insn->op_str);

        cs_riscv *riscv = &(insn->detail->riscv);
}


void print_run_cpu(csh handle, const uint8_t *code_ptr, size_t code_size, uint64_t address, cs_insn *insn, uint64_t main_addr) {
	//print the header of the instruction
	printf("int64_t run_cpu() {\n");
	//initialize regfile
	printf("    RegisterFile cpu = {0};\n");
	//initialize the stack pointer
	printf("    cpu.regs[2] = 0x7FFFFFF0;\n");

	//need to add a goto to main here now
	printf("    goto L_0x%ld;\n", main_addr);

	while (code_size > 0) {
		bool success = cs_disasm_iter(handle, &code_ptr, &code_size, &address, insn);

		if (success) {
			translate_to_c(handle, insn);
		} else {
			if (code_size >= 4) {
				uint64_t raw_instr = *(uint64_t*)code_ptr;

				printf("    // Custom Instruction: 0x%08lx\n", raw_instr);
				//need to add custom logic for the custom instructions or so we ignore them here?


				//advance pointers manually
				code_ptr += 4;
				code_size -= 4;
				address += 4;

			} else {
				break; //trailing whatever
			}
		}
	
	}
	printf("    return cpu.a0;\n");
	printf("}\n");
}




int main(int argc, char** argv) {
        if (argc < 2) {
                perror("Usage: ./translator <riscv_elf>\n");
                return 1;
        }

	//LOOKING AT THE WHOLE ELF
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("Error opening ELF for entry point\n");
		exit(1);
	}
	
	struct stat st;
	fstat(fd, &st);

	std::vector<uint8_t> elf_buffer(st.st_size);
	if (read(fd, elf_buffer.data(), st.st_size) != st.st_size) {
		perror("Error reading elf\n");
		exit(1);
	}
	close(fd);

	Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf_buffer.data();
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		perror("Not a valid ELF file\n");
		exit(1);
	}

	//entry point should be main because I'm compiling it that way
	//TODO: do I still need to do it like that??
	uint64_t entry_point = ehdr->e_entry;


	//get pointer to section headers
	Elf64_Shdr* shdrs = (Elf64_Shdr*)(elf_buffer.data() + ehdr->e_shoff);
	//find the section header strings table
	char* shstrtab = (char*)(elf_buffer.data() + shdrs[ehdr->e_shstrndx].sh_offset);

	//init vals needed to isolate the text section
	uint8_t* text_section_ptr = (uint8_t*)NULL;
	uint64_t text_section_addr = 0;
	size_t text_size = 0;


	//iterate through the section headers
	for (int i = 0; i < ehdr->e_shnum; i++) {
        	//collect the name of this header
		std::string sname = shstrtab + shdrs[i].sh_name;
        
        	// Locate text section
        	if (sname == ".text") {
            		text_section_ptr = elf_buffer.data() + shdrs[i].sh_offset;
            		text_section_addr = shdrs[i].sh_addr;
            		text_size = shdrs[i].sh_size;
        	}
	}


	if (!text_section_ptr) {
		perror("couldn't find a text section\n");
		exit(1);
	}

	
	//init capstone for dissassembly
	csh handle;
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle) != CS_ERR_OK) {
		perror("capstone init failed\n");
		exit(1);
	}

	//tells capstone to populate the detail struct
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_insn *insn = cs_malloc(handle);
	
	print_run_cpu(handle, text_section_ptr, text_size, text_section_addr, insn, entry_point);
	
	return 0;
}

