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
#include <map>

//print the C header for the stuff we need to run
void print_header() {
	//libraries needed by default
	//TODO: check if we can take any of these out
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

	//create variables for the memory pointer
        printf("uint8_t* memory = NULL;\n");
	printf("\n");
}


//prints logic to set up the memory space and read in the PTLOAD sections of the ELF
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

	printf("    // 4. Load Program Headers\n");
	printf("    Elf64_Phdr* phdrs = malloc(sizeof(Elf64_Phdr) * ehdr.e_phnum);\n");
	printf("    lseek(fd, ehdr.e_phoff, SEEK_SET);\n");
	printf("    if (!read(fd, phdrs, sizeof(Elf64_Phdr) * ehdr.e_phnum)) {\n\n");
	printf("        fprintf(stderr, \"Error: failed to read program headers\\n\"); exit(1);\n");
	printf("    }\n\n");

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

	printf("    int64_t retval = 0;\n");
	printf("    init_memory(argv[1]);\n");

	printf("    retval = run_cpu();\n");
	printf("    return retval;\n");
	printf("}\n");
}



//---------------SYMBOL TABLE PARSING FOR FUNCTION REPLACEMENT-----------------//

std::map<uint64_t, std::string> collect_symbols(uint8_t* elf_start) {
	std::map<uint64_t, std::string> symbol_map;

	Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf_start;

	Elf64_Shdr* shdrs = (Elf64_Shdr*)(elf_start + ehdr->e_shoff);
	char* shstrtab = (char*)(elf_start + shdrs[ehdr->e_shstrndx].sh_offset);

	//find the section headers
	//TODO: expand this function to do the logic that locates the text section (currently handled by main)
	for (int i = 0; i < ehdr->e_shnum; i++) {
		//SHT_SYMTAB (static symbols) or SHT_DYNSYM (dynamic symbols)
		if (shdrs[i].sh_type == SHT_SYMTAB || shdrs[i].sh_type == SHT_DYNSYM) {
			Elf64_Sym* syms = (Elf64_Sym*)(elf_start + shdrs[i].sh_offset);
			int symbol_count = shdrs[i].sh_size / sizeof(Elf64_Sym);

			// The string table for this symbol table is linked via sh_link
			char* strtab = (char*)(elf_start + shdrs[shdrs[i].sh_link].sh_offset);

			for (int j = 0; j < symbol_count; j++) {
				// Get the name from the string table
				std::string name = strtab + syms[j].st_name;

				// Only map function symbols (STT_FUNC) that have a name and address
				if (!name.empty() && syms[j].st_value != 0) {
					// STB_GLOBAL or STB_LOCAL is fine
					symbol_map[syms[j].st_value] = name;

					//logging
					fprintf(stderr, "[Symbol Mapper] Found %s at 0x%lx\n", name.c_str(), syms[j].st_value);
				}
			}
		}
	}

	return symbol_map;
}







//-----------------------------------------------------------------------------//





//-----------BRANCH COLLECTION HELPERS + regtoindex translation-------------//

//boolean function to determine if an instruction is labeled by capstones
//branching instruction labels
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

//given a branching instruction, we return the target address
//for jumps not calculable by this function we are likely 
//jumping to another region of memory like the bss or something
//and we wont need a target there
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

//convert the register ID to an index for my reg file union
int reg_to_index(unsigned int reg) {
        if (reg >= RISCV_REG_X0 && reg <= RISCV_REG_X31) {
                return reg - RISCV_REG_X0;
        }
        std::cerr << "register index translation failed\n" << std::endl;
        return -1;
}

//----------------------------------------------------//

//------------------BRACNH TARGET COLLECTION----------//

std::set<uint64_t> collect_branch_targets(csh handle, const uint8_t *code_ptr, size_t code_size, uint64_t address, cs_insn *insn) {

        //collect all branchh targets and return the set
        std::set<uint64_t> targets;

        //loop over the instructions
        while (code_size > 0) {
                uint64_t current_insn_address = address;
                bool success = cs_disasm_iter(handle, &code_ptr, &code_size, &address, insn);
		cs_riscv *riscv = &(insn->detail->riscv);

		if (success) {
			//first check if we have auipc and jalr combo and we will calculate address for targets
			if (insn->id == RISCV_INS_AUIPC) {
				uint64_t pc = insn->address;
				int64_t immediate = riscv->operands[1].imm;
				int rd = reg_to_index(riscv->operands[0].reg);
				uint64_t val_in_rd = pc + immediate;
				
				if (code_size > 4) {
					uint64_t current_insn_address = address;
					bool success = cs_disasm_iter(handle, &code_ptr, &code_size, &address, insn);
					cs_riscv *riscv = &(insn->detail->riscv);

					if (success) {
						if (insn->id == RISCV_INS_JALR) {
							//is rs1 the same register calculated in auipc
							if (reg_to_index(riscv->operands[1].reg) == rd) {
								//do the jalr calculation and add to targets
								uint64_t target = (val_in_rd + riscv->operands[2].imm) & ~1;
								targets.insert(target);
								//add next instruction after call for function return
								targets.insert(insn->address + 4);
								fprintf(stderr, "[Collector] Found AUIPC+JALR pair. Target: 0x%lx\n", target);
							}
						}
					}
				}				
			}
			//if aiupc and the next is not a jalr, it will fall through and still catch branches

			//check if it is a branch and if it is and the immediate exists add to targets
                        if (is_branch(insn) && insn->id != RISCV_INS_JALR) {
                                int64_t insn_target = get_branch_target(insn);
                                if (insn_target != 0) {
                                        fprintf(stderr, "[Collector] branch at 0x%lx to 0x%lx\n", current_insn_address, insn_target);
                                        targets.insert(insn_target);
                                }
			}
			
		} else {
			//failed, likely custom instruction, increase pointers
			//custom instructions will not result in branches
                	code_ptr += 4;
                	code_size -= 4;
                	address += 4;
		}
        }

        return targets;
}

//---------------------------------------------------//

//-----------------------LOGIC PRINTING-------------//


void translate_to_c(csh handle, cs_insn *insn, std::set<uint64_t>& targets, uint64_t main_addr) {
        printf("    // %s %s\n", insn->mnemonic, insn->op_str);
	//populate details structure
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

		//add word
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

		//add word instruction
                case RISCV_INS_ADDW: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int rs1 = reg_to_index(riscv->operands[1].reg);
                        int rs2 = reg_to_index(riscv->operands[2].reg);
                        //0 reg should not be added into
                        //cast to 32 and then back so overflow works the same
                        if (rd != 0) printf("    cpu.regs[%d] = (int64_t)(int32_t)(cpu.regs[%d] + cpu.regs[%d]);\n", rd, rs1, rs2);
                        break;
                }

                //sub register instructions
                case RISCV_INS_SUB: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int rs1 = reg_to_index(riscv->operands[1].reg);
                        int rs2 = reg_to_index(riscv->operands[2].reg);
                        //0 reg should not be added into
                        if (rd != 0) printf("    cpu.regs[%d] = cpu.regs[%d] - cpu.regs[%d];\n", rd, rs1, rs2);
                        break;
                }

		//subtract word instruction
                case RISCV_INS_SUBW: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int rs1 = reg_to_index(riscv->operands[1].reg);
                        int rs2 = reg_to_index(riscv->operands[2].reg);
                        //0 reg should not be added into
                        //cast to 32 and then back so overflow works the same
                        if (rd != 0) printf("    cpu.regs[%d] = (int64_t)(int32_t)(cpu.regs[%d] - cpu.regs[%d]);\n", rd, rs1, rs2);
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
                        //TODO: is this right for storing a 32 bit value? will this be in the right place in memory???
                        printf("    *(int32_t*)(memory + cpu.regs[%d] + %ld) = (int32_t)(cpu.regs[%d]);\n", base_reg, offset, rs2);
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

                case RISCV_INS_LUI: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int64_t imm = riscv->operands[1].imm;
                        //TODO: shift left 12 to place value into upper part of 32 bit space???? is this right??
                        if (rd != 0) printf("    cpu.regs[%d] = (int64_t)(int32_t)(0x%lx << 12);\n", rd, imm);
                        break;
                }

		case RISCV_INS_AUIPC: {
			int rd = reg_to_index(riscv->operands[0].reg);
			int64_t imm = (int64_t)riscv->operands[1].imm << 12;	
			uint64_t pc = insn->address;

			if (rd != 0) {
				// rd = current_pc + immediate
				printf("    cpu.regs[%d] = 0x%lxULL + %ldLL;\n", rd, pc, imm);
			}
			break;
		}


		case RISCV_INS_JALR: {
			if (!riscv->operands[0].reg && !riscv->operands[1].reg) {
				//ret instruction
				printf("    goto *(void *)cpu.regs[1];\n");
			} else {
				//regular jalr
				printf("//-------NON RET JALR ENCOUNTERED, THIS IS DISSALLOWED-----------\n");
			}
			break;
		}

                default:
                        printf("//-------UNDEFINED INSTRUCTION IN SWITCH, ADD A CASE FOR ABOVE----------\n");
                        break;

        }


}

//used to determine if we are replacing
bool is_replaceable_function(std::string func_name) {
	if (func_name == "printf") {
		return true;
	} else {
		return false;
	}	

}

//print the function that acts as the functional eq of the text section
void print_run_cpu(csh handle, const uint8_t *code_ptr, size_t code_size, uint64_t address, cs_insn *insn, uint64_t main_addr, std::set<uint64_t>& targets, std::map<uint64_t, std::string>& symbols) {
	printf("int64_t run_cpu() {\n");
	printf("    RegisterFile cpu = {0};\n");
	printf("    cpu.regs[2] = 0x7FFFFFF0;\n");
	printf("    cpu.regs[1] = (int64_t)&&L_RETFROMMAIN;\n");
	printf("    goto L_0x%lx;\n", main_addr);

	while (code_size > 0) {
		//get current insn
		if (!cs_disasm_iter(handle, &code_ptr, &code_size, &address, insn)) {
			// Handle custom
			code_ptr += 4;
			code_size -= 4;
			address += 4;
			printf("//-------------CUSTOM INSTRUCTION ENCOUNTERED------------\n");
			continue;
        	}

        	// Print label if it's a branch target
		if (targets.count(insn->address) || insn->address == main_addr) {
			printf("L_0x%lx:\n", insn->address);
		}

		//populate the details structure
		cs_riscv *riscv = &(insn->detail->riscv);

        	//CHECK FOR AUIPC + JALR
		if (insn->id == RISCV_INS_AUIPC && code_size >= 4) {
			int rd = reg_to_index(riscv->operands[0].reg);
			int64_t auipc_imm = riscv->operands[1].imm;
			uint64_t auipc_pc = insn->address;

			//NEXT instruction peak, get tmp values to inspect
			cs_insn *next_insn = cs_malloc(handle);
			const uint8_t *tmp_ptr = code_ptr;
			size_t tmp_size = code_size;
			uint64_t tmp_addr = address;

			if (cs_disasm_iter(handle, &tmp_ptr, &tmp_size, &tmp_addr, next_insn)) {

                		cs_riscv *next_riscv = &(next_insn->detail->riscv);
                
                		// If it's a JALR using the register we just set	
				if (next_insn->id == RISCV_INS_JALR && reg_to_index(next_riscv->operands[1].reg) == rd) {
					uint64_t target = (auipc_pc + auipc_imm + next_riscv->operands[2].imm) & ~1ULL;
					uint64_t ret_addr = next_insn->address + 4;
					auto find_iterator = symbols.find(target);
					
					//TODO: This identifies the symbol for the target here, I need to be able to compile the riscv stuff
					//with the stdlib stuff in order to test if this works
					//when I can do that we need to write a function that identifies which one we are looking at and replaces with the
					//appropriate call. once this works, we will add the same functionality to JAL instructions
					if (find_iterator != symbols.end()) {
						//symbol exists
						//gets the symbol string: printf("%s\n", find_iterator->second.c_str());
						if (is_replaceable_function(find_iterator->second)) {
							printf("IDENTIFIED PRINTF\n");
						}	
					} else {
						//doesn't exist
					}
		
					printf("    //AUIPC + JALR -> Static Goto\n");
					printf("    cpu.regs[1] = (int64_t)&&L_0x%lx;\n", ret_addr);
                    			printf("    goto L_0x%lx;\n", target);

                    			// Consumed the next instruction, so update real pointers
                    			code_ptr = tmp_ptr;
                    			code_size = tmp_size;
                    			address = tmp_addr;
                    			cs_free(next_insn, 1);
                    			continue; // Done with this pair
                		}
			}
		
			cs_free(next_insn, 1);
        	}

        	// If we didn't encounter a auipc + jalr pair
        	translate_to_c(handle, insn, targets, main_addr);
	}
	
	//label pointer to this label will be pushed onto stack
	//at RIP before entering main, if we see it in a ret, jump here	
	printf("\nL_RETFROMMAIN:\n");
	printf("    return cpu.regs[10];\n");
	printf("}\n");
}


//--------------------------------------------//

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

	//check elf structure
	Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf_buffer.data();
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		perror("Not a valid ELF file\n");
		exit(1);
	}

	//entry point should be main because we are compiling it that way
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
			//get info required to isolate text section
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

	//tells capstone we will need the details of each instruction
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_insn *insn = cs_malloc(handle);

	//collect branch targets for label printing in run_cpu
	std::set<uint64_t> targets = collect_branch_targets(handle, text_section_ptr, text_size, text_section_addr, insn); //parse for targets
	std::map<uint64_t, std::string> symbols = collect_symbols(elf_buffer.data()); //symbol table parse

	//test symbols
	//TODO: delete
	//for (const auto& [addr, name] : symbols) {
        //	std::cout <<  std::hex << addr << ": " << name << "\n";
    	//}
	


	//print the file (will go to stdout, needs to be captured)
	print_header();
	print_init_memory();
	print_run_cpu(handle, text_section_ptr, text_size, text_section_addr, insn, entry_point, targets, symbols);
	print_main();
	return 0;
}

