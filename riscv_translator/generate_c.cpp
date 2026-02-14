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
	//initialize regfile
	printf("RegisterFile cpu = {0};\n");
	//create variables for the memory pointer and the program entry point
        printf("uint8_t* memory = NULL;\n");
	printf("uint64_t starting_address = 0;\n\n");
}

//sets up the memory space and reads in the PTLOAD sections of the ELF
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
	printf("}\n\n");
	}

//prints main
void print_main() {
        printf("\nint main(int argc, char** argv) {\n");
        printf("    if (argc < 2) { printf(\"Usage: %%s <original_elf>\\n\", argv[0]); return 1; }\n");
        printf("    init_memory(argv[1]);\n");

	//initialize the stack pointer
	printf("    cpu.regs[2] = 0x7FFFFFF0;\n");
	
        printf("    run_cpu(starting_address);\n");
        printf("    return cpu.a0;\n");
        printf("}\n");
}

bool is_branch(cs_insn *insn) {
	cs_detail *detail = insn->detail;
	if (!detail) return false;

	//find the group labels that indicate a branching RISCV instruction
	for (int i = 0; i < detail->groups_count; i++) {
		// Look for the "Jump" or "Branch Relative" categories
		if (detail->groups[i] == RISCV_GRP_JUMP || 
			detail->groups[i] == RISCV_GRP_BRANCH_RELATIVE ||
			detail->groups[i] == RISCV_GRP_CALL) {
			return true;
		}
	}
	return false;
}


uint64_t get_branch_target(cs_insn *insn) {
    cs_riscv *riscv = &insn->detail->riscv;

    //is this a real instruction
    if (riscv->op_count > 0) {
        cs_riscv_op *last_op = &riscv->operands[riscv->op_count - 1];

	//if we have an immediate branch target
        if (last_op->type == RISCV_OP_IMM) {
            //Add the instruction address to the relative offset
            return (uint64_t)(insn->address + last_op->imm);
        }
    }
    return 0; 
}


int reg_to_index(unsigned int reg) {
	if (reg >= RISCV_REG_X0 && reg <= RISCV_REG_X31) {
		return reg - RISCV_REG_X0;
	}
	std::cerr << "register index translation failed\n" << std::endl;
	return -1;
}


void translate_to_c(csh handle, cs_insn *insn, const std::set<uint64_t>& targets) {
   	// Check the count
	int is_target = targets.count(insn->address);
    
	// If it's a target, print the label
	// NOTE: Need to add labels for the instruction immediately after a call or jalr 
	if (is_target) {
		printf("L_0x%lx:\n", insn->address);
	}

	printf("    // %s %s  is target: %d\n", insn->mnemonic, insn->op_str, is_target);

	cs_riscv *riscv = &(insn->detail->riscv);

	switch (insn->id) {
		//detect instruction type and translate
		
		//add immediate instructions
		case RISCV_INS_ADDI: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int rs1 = reg_to_index(riscv->operands[1].reg);
			int64_t imm = riscv->operands[2].imm;
			//0 reg should not be added into
			if (rd != 0) printf("    cpu.regs[%d] = cpu.regs[%d] + %ld;\n", rd, rs1, imm);
			break;
		}
		case RISCV_INS_ADDIW: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int rs1 = reg_to_index(riscv->operands[1].reg);
			int64_t imm = riscv->operands[2].imm;
			//0 reg should not be added into
			//cast to 32 then back to 64 to make the overflow behave the same
			if (rd != 0) printf("    cpu.regs[%d] = (int64_t)(int32_t)(cpu.regs[%d] + %ld);\n", rd, rs1, imm);
			break;
		}
		
		//add register instructions
		case RISCV_INS_ADD: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int rs1 = reg_to_index(riscv->operands[1].reg);
			int rs2 = reg_to_index(riscv->operands[2].reg);
			//0 reg should not be added into
			if (rd != 0) printf("    cpu.regs[%d] = cpu.regs[%d] + cpu.regs[%d];\n", rd, rs1, rs2);
			break;
		}
		case RISCV_INS_ADDW: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int rs1 = reg_to_index(riscv->operands[1].reg);
			int rs2 = reg_to_index(riscv->operands[2].reg);
			//0 reg should not be added into
			//cast to 32 and then back so overflow works the same
			if (rd != 0) printf("    cpu.regs[%d] = (int64_t)(int32_t)(cpu.regs[%d] + cpu.regs[%d]);\n", rd, rs1, rs2);
			break;
		}

		//multiply instructions
		case RISCV_INS_MUL: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int rs1 = reg_to_index(riscv->operands[1].reg);
			int rs2 = reg_to_index(riscv->operands[2].reg);
			//0 reg should not be added into
			if (rd != 0) printf("    cpu.regs[%d] = cpu.regs[%d] * cpu.regs[%d];\n", rd, rs1, rs2);
			break;
		}
		case RISCV_INS_MULW: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int rs1 = reg_to_index(riscv->operands[1].reg);
			int rs2 = reg_to_index(riscv->operands[2].reg);
			//0 reg should not be added into
			if (rd != 0) printf("    cpu.regs[%d] = (uint64_t)(uint32_t)(cpu.regs[%d] * cpu.regs[%d]);\n", rd, rs1, rs2);
			break;
		}


		//branching instructions
		//Branch equal
		case RISCV_INS_BEQ: {
			int rs1 = reg_to_index(riscv->operands[0].reg);
			int rs2 = 0;
			uint64_t target = get_branch_target(insn);
			
			//beqz will have the same enum but only two operands for the register and target imm
			if (riscv->op_count == 3) {
				rs2 = reg_to_index(riscv->operands[1].reg);
			} else if (riscv->op_count == 2) {
				rs2 = 0;
			} else {
				std::cerr << "invalid opcount for branch equal instr" << std::endl;
			}

			printf("    if (cpu.regs[%d] == cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			break;
		}

	
		//branch not equal
		case RISCV_INS_BNE: {
			int rs1 = reg_to_index(riscv->operands[0].reg);
			int rs2 = 0;
			uint64_t target = get_branch_target(insn);
			
			//bnez will have the same enum but only two operands for the register and target imm
			if (riscv->op_count == 3) {
				rs2 = reg_to_index(riscv->operands[1].reg);
			} else if (riscv->op_count == 2) {
				rs2 = 0;
			} else {
				std::cerr << "invalid opcount for branch equal instr" << std::endl;
			}

			printf("    if (cpu.regs[%d] != cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			break;
		}

		//branch less than unsigned
		case RISCV_INS_BLTU: {
			int rs1 = reg_to_index(riscv->operands[0].reg);
			int rs2 = reg_to_index(riscv->operands[1].reg);
			uint64_t target = get_branch_target(insn);
			
			//need to cast register values to unsigned
			printf("    if ((uint64_t)cpu.regs[%d] < (uint64_t)cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			break;	
		}

		//branch less than signed 
		case RISCV_INS_BLT: {
			int rs1 = reg_to_index(riscv->operands[0].reg);
			int rs2 = reg_to_index(riscv->operands[1].reg);
			uint64_t target = get_branch_target(insn);
			
			//no cast
			printf("    if (cpu.regs[%d] < cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			break;
		}

		//unconditional jumps
		case RISCV_INS_JAL: {
			//TODO: add linking mechanic for jump and link when we need it (not yet for factorial)
			if (riscv->op_count == 1) {
				//just a regular jump (no link)
				uint64_t target = get_branch_target(insn);
				printf("    goto L_0x%lx;\n", target);
			}
			break;
		}

		//store double instruction
		case RISCV_INS_SD: {
			int rs2 = reg_to_index(riscv->operands[0].reg);
			int base_reg = reg_to_index(riscv->operands[1].mem.base);
			int64_t offset = riscv->operands[1].mem.disp;
			printf("    *(int64_t*)(memory + cpu.regs[%d] + %ld) = cpu.regs[%d];\n", base_reg, offset, rs2);
			break;
		}

		//store word instruction
		case RISCV_INS_SW: {
			int rs2 = reg_to_index(riscv->operands[0].reg);
			int base_reg = reg_to_index(riscv->operands[1].mem.base);
			int64_t offset = riscv->operands[1].mem.disp;
			printf("    *(int32_t*)(memory + cpu.regs[%d] + %ld) = (int64_t)(int32_t)(cpu.regs[%d]);\n", base_reg, offset, rs2);
			break;
		}


		//load double instruction
		case RISCV_INS_LD: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int base_reg = reg_to_index(riscv->operands[1].mem.base);
			int64_t offset = riscv->operands[1].mem.disp;
			//dont ever load to reg 0
			if (rd != 0) printf("    cpu.regs[%d] = *(int64_t*)(memory + cpu.regs[%d] + %ld);\n", rd, base_reg, offset);
			break;
		}

		//load word instruction
		case RISCV_INS_LW: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int base_reg = reg_to_index(riscv->operands[1].mem.base);
			int64_t offset = riscv->operands[1].mem.disp;
			//dont ever load to reg 0
			if (rd != 0) printf("    cpu.regs[%d] = (int64_t)*(int32_t*)(memory + cpu.regs[%d] + %ld);\n", rd, base_reg, offset);
			break;
		}

		//load word instruction unsigned
		case RISCV_INS_LWU: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int base_reg = reg_to_index(riscv->operands[1].mem.base);
			int64_t offset = riscv->operands[1].mem.disp;
			//dont ever load to reg 0
			if (rd != 0) printf("    cpu.regs[%d] = (int64_t)*(uint32_t*)(memory + cpu.regs[%d] + %ld);\n", rd, base_reg, offset);
			break;
		}

		case RISCV_INS_JALR: {
			//TODO: only a basic ret from main right now, need to update to handle actual jalr not ret from main
			printf("    return;\n");
			break;
		}	     

		default:
			printf("//-------UNDEFINED INSTRUCTION IN SWITCH, ADD A CASE FOR ABOVE----------\n");
			break;

	}
}

void print_run_cpu(csh handle, const uint8_t *code_ptr, size_t code_size, uint64_t address, cs_insn *insn, std::set<uint64_t> targets) {
	//print the header of the instruction
	printf("void run_cpu(uint64_t entry_point) {\n");
	while (code_size > 0) {
		bool success = cs_disasm_iter(handle, &code_ptr, &code_size, &address, insn);

		if (success) {
			//print the functionally equivalent C for a given instruction
			translate_to_c(handle, insn, targets);
		} else {
			if (code_size >= 4) {
				uint64_t raw_instr = *(uint64_t*)code_ptr;

				printf("    // Custom Instruction: 0x%08lx\n", raw_instr);

				//advance pointers manually
				code_ptr += 4;
				code_size -= 4;
				address += 4;

			} else {
				break; //trailing whatever
			}
		}
	
	}
	printf("}\n");
}


std::set<uint64_t> collect_branch_targets(csh handle, const uint8_t *code_ptr, size_t code_size, uint64_t address, cs_insn *insn) {
	
	//collect all branchh targets and return the set
	std::set<uint64_t> targets;

	//loop over the instructions
	while (code_size > 0) {
		uint64_t current_insn_address = address;
		bool success = cs_disasm_iter(handle, &code_ptr, &code_size, &address, insn);
		
		//dissassembled successfully
		if (success) {
			//check if it is a branch and if it is and the immediate exists add to targets
			if (is_branch(insn)) {
				int64_t insn_target = get_branch_target(insn);
				if (insn_target != 0) {
					fprintf(stderr, "[Collector] branch at 0x%lx to 0x%lx\n", current_insn_address, insn_target);
					targets.insert(insn_target);
				}	
			}

		//failed, likely custom instruction, increase pointers
		} else {
			code_ptr += 4;
			code_size -= 4;
			address += 4;
		}
	}

	return targets;
}


int main(int argc, char** argv) {
        if (argc < 2) {
                std::cerr << "Usage: ./translator <riscv_text_section> <riscv_elf>" << std::endl;
                return 1;
        }

	//LOOKKING AT ONLY THE TEXT SECTION
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


	//LOOKING AT THE WHOLE ELF
	int fd = open(argv[2], O_RDONLY);
	if (fd < 0) {
		perror("Error opening ELF for entry point\n");
		exit(1);
	}

	Elf64_Ehdr ehdr;

	if (read(fd, &ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
		perror("Error reading elf header in generator\n");
		exit(1);
	}

	if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        	ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        	std::cerr << "Error: Not a valid ELF file." << std::endl;
        	exit(1);
    	}

	if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        	std::cerr << "Error: Not a 64-bit ELF file." << std::endl;
        	exit(1);
    	}

	close(fd);

	//OUTPUT THE FUNCTIONALLY EQUIVALENT C
        cs_insn *insn = cs_malloc(handle);
	uint64_t elf_entry = ehdr.e_entry;
	
        print_header();
        print_init_memory();

	const uint8_t *code_ptr = buffer.data();
	size_t code_size = buffer.size();
	std::set<uint64_t> targets = collect_branch_targets(handle, code_ptr, code_size, elf_entry, insn);

	code_ptr = buffer.data(); //resets
	code_size = buffer.size();

	print_run_cpu(handle, code_ptr, code_size, elf_entry, insn, targets);

	print_main();

        cs_free(insn, 1);
        cs_close(&handle);
        return 0;
}

