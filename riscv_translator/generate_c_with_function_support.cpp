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

struct SymbolInfo {
	std::string name;
	uint64_t size;
};

//tag to tell run_cpu function if we are sending to sentry
bool trusted = true;



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

	//define struct needed to pack values to send to sentry
	//printf("#define	IS_BRANCH (1 << 0)\n");
	//printf("#define JUMP_TAKEN (1 << 1)\n");
	//printf("#define IS_LOAD   (1 << 2)\n");
	//printf("#define IS_STORE  (1 << 3)\n");

	//printf("struct ExecInfo {\n");
    	//printf("    uint64_t result_value; // The value written to RD or memory\n");
    	//printf("    uint64_t target_pc;    // Used if the instruction was an indirect jump\n");
    	//printf("    unsigned int control;  // Bitflags: [WasBranchTaken | IsLoad | IsStore | IsBranch]\n");
	//printf("};\n");


	//buffer for holding results before sending
	//and global to track how full it is
	printf("#define BUFFER_SIZE (1 << 26)\n"); //64 MB
	//printf("#define BUFFER_SIZE 2048\n"); //64 MB
	printf("#define BUFFER_FLUSH_MARGIN 64\n");
	printf("uint8_t buffer[BUFFER_SIZE];\n");
	printf("int bufferPos = 0;\n");
	printf("static FILE* sentry_log_file = NULL;\n");

	printf("enum {\n");
	printf("    TAG_VAL = 0x00,\n");
	printf("    TAG_BRANCH_NOT_TAKEN = 0x01,\n");
	printf("    TAG_BRANCH_TAKEN = 0x02,\n");
	printf("    TAG_MEM = 0x03,\n");
	printf("};\n\n");
	
	printf("static inline __attribute__((always_inline))\n");
	printf("void emit_u8(uint8_t x) {\n");
	printf("    buffer[bufferPos++] = x;\n");
	printf("}\n\n");

	printf("static inline __attribute__((always_inline))\n");
	printf("void emit_u64(uint64_t x) {\n");
	printf("    __builtin_memcpy(&buffer[bufferPos], &x, 8);\n");
	printf("    bufferPos += 8;\n");
	printf("}\n\n");

	printf("static inline __attribute__((always_inline))\n");
	printf("void trace_val(uint64_t value) {\n");
	printf("    emit_u64(value);\n");
	printf("}\n\n");

	printf("static inline __attribute__((always_inline))\n");
	printf("void trace_branch_not_taken(void) {\n");
	printf("    emit_u8(TAG_BRANCH_NOT_TAKEN);\n");
	printf("}\n\n");

	printf("static inline __attribute__((always_inline))\n");
	printf("void trace_branch_taken(uint64_t target) {\n");
	printf("    emit_u8(TAG_BRANCH_TAKEN);\n");
	printf("    emit_u64(target);\n");
	printf("}\n\n");

	printf("static inline __attribute__((always_inline))\n");
	printf("void trace_mem(uint64_t addr, uint64_t value) {\n");
	printf("    emit_u8(TAG_MEM);\n");
	printf("    emit_u64(addr);\n");
	printf("    emit_u64(value);\n");
	printf("}\n\n");	

	//tell compiler to expect not to flush 
	printf("void maybe_flush_buffer() {\n");
	printf("    if (__builtin_expect(bufferPos > BUFFER_SIZE - BUFFER_FLUSH_MARGIN, 0)) {\n");
	printf("        fwrite(buffer, sizeof(uint8_t), bufferPos, sentry_log_file);\n");
	printf("        bufferPos = 0; // Reset counter after flush\n");
	printf("    }\n");
	printf("}\n\n");

	printf("void flush_buffer_final() {\n");
	printf("    if (bufferPos > 0) {\n");
	printf("        fwrite(buffer, sizeof(uint8_t), bufferPos, sentry_log_file);\n");
	printf("        bufferPos = 0; // Reset counter after flush\n");
	printf("    }\n");
	printf("}\n\n");

	//nutered for testing
	//inlining this function call does not seem to reduce overhead by any amount??	
	//printf("static inline __attribute__((always_inline))\n");
	//printf("void send_to_sentry(struct ExecInfo toSend) {\n");
	//printf("    buffer[itemsInBuffer++] = toSend;\n\n");
	//printf("    // If buffer is full, trigger a flush\n");
	//printf("    if (itemsInBuffer >= BUFFER_SIZE) {\n");
	//printf("        flush_to_disk();\n");
	//printf("    }\n");
	//printf("}\n\n");





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
	printf("    //sentry_log_file = fopen(\"/dev/null\", \"ab\");\n"); //moved for optimization reasons
	printf("    sentry_log_file = fopen(\"new_sentry_trace.log\", \"ab\");\n"); //moved for optimization reasons

	printf("    retval = run_cpu();\n");
	printf("    return retval;\n");
	printf("}\n");
}



//---------------SYMBOL TABLE PARSING FOR FUNCTION REPLACEMENT-----------------//



std::map<uint64_t, SymbolInfo> collect_symbols(uint8_t* elf_start) {
	std::map<uint64_t, SymbolInfo> symbol_map;

	Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf_start;
	Elf64_Shdr* shdrs = (Elf64_Shdr*)(elf_start + ehdr->e_shoff);
	char* shstrtab = (char*)(elf_start + shdrs[ehdr->e_shstrndx].sh_offset);

	uint64_t plt_base_addr = 0;

	//find the section headers
	//TODO: maybe expand this function to do the logic that locates the text section (currently handled by main)
	for (int i = 0; i < ehdr->e_shnum; i++) {
		//SHT_SYMTAB (static symbols) or SHT_DYNSYM (dynamic symbols)
		
		std::string sname = shstrtab + shdrs[i].sh_name;
		if (sname == ".plt") {
			plt_base_addr = shdrs[i].sh_addr;
		}

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
					symbol_map[syms[j].st_value] = {name, syms[j].st_size};

					fprintf(stderr, "[Symbol Mapper] Found %s at 0x%lx (size: %lu bytes)\n", name.c_str(), syms[j].st_value, syms[j].st_size);
				}
			}
		}
	}

	//find named stubs in the plt to look for external functions to be replaced
	if (plt_base_addr != 0) {
		for (int i = 0; i < ehdr->e_shnum; i++) {
			if (shdrs[i].sh_type == SHT_RELA) {
				std::string sname = shstrtab + shdrs[i].sh_name;
				if (sname == ".rela.plt") {
					Elf64_Rela* relas = (Elf64_Rela*)(elf_start + shdrs[i].sh_offset);
					int count = shdrs[i].sh_size / sizeof(Elf64_Rela);

					// Find the dynamic symbol table (.dynsym) used by this relocation section
					Elf64_Shdr* dynsym_shdr = &shdrs[shdrs[i].sh_link];
					Elf64_Sym* dynsyms = (Elf64_Sym*)(elf_start + dynsym_shdr->sh_offset);
					char* dynstrtab = (char*)(elf_start + shdrs[dynsym_shdr->sh_link].sh_offset);

					// The first stub starts after the 32-byte PLT header
					uint64_t current_stub_addr = plt_base_addr + 32;

					for (int j = 0; j < count; j++) {
						int sym_idx = ELF64_R_SYM(relas[j].r_info);
						std::string sym_name = dynstrtab + dynsyms[sym_idx].st_name;

						// Map the executable stub address (0x18f0 etc) to the function name
						symbol_map[current_stub_addr] = {sym_name + "@plt", 16};

						fprintf(stderr, "[PLT Mapper] Mapped stub at 0x%lx to %s\n", current_stub_addr, sym_name.c_str());

						// Move to next 16-byte stub
						current_stub_addr += 16;
					}
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
			if (trusted) {
				printf("    {\n");
				printf("        trace_val(cpu.regs[%d]);\n", rd);
				printf("    }\n");
			}
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
			if (trusted) {
				printf("    {\n");
				printf("        trace_val(cpu.regs[%d]);\n", rd);
				printf("    }\n");
			}
                        break;
                }

                //add register instructions
                case RISCV_INS_ADD: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int rs1 = reg_to_index(riscv->operands[1].reg);
                        int rs2 = reg_to_index(riscv->operands[2].reg);
                        //0 reg should not be added into
                        if (rd != 0) printf("    cpu.regs[%d] = cpu.regs[%d] + cpu.regs[%d];\n", rd, rs1, rs2);
			if (trusted) {
				printf("    {\n");
				printf("        trace_val(cpu.regs[%d]);\n", rd);
				printf("    }\n");
			}
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
			if (trusted) {
				printf("    {\n");
				printf("        trace_val(cpu.regs[%d]);\n", rd);
				printf("    }\n");
			}
                        break;
                }

                //sub register instructions
                case RISCV_INS_SUB: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int rs1 = reg_to_index(riscv->operands[1].reg);
                        int rs2 = reg_to_index(riscv->operands[2].reg);
                        //0 reg should not be added into
                        if (rd != 0) printf("    cpu.regs[%d] = cpu.regs[%d] - cpu.regs[%d];\n", rd, rs1, rs2);
			if (trusted) {
				printf("    {\n");
				printf("        trace_val(cpu.regs[%d]);\n", rd);
				printf("    }\n");
			}
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
			if (trusted) {
				printf("    {\n");
				printf("        trace_val(cpu.regs[%d]);\n", rd);
				printf("    }\n");
			}
                        break;
                }

                //multiply instructions
                case RISCV_INS_MUL: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int rs1 = reg_to_index(riscv->operands[1].reg);
                        int rs2 = reg_to_index(riscv->operands[2].reg);
                        //0 reg should not be added into
                        if (rd != 0) printf("    cpu.regs[%d] = cpu.regs[%d] * cpu.regs[%d];\n", rd, rs1, rs2);
			if (trusted) {
				printf("    {\n");
				printf("        trace_val(cpu.regs[%d]);\n", rd);
				printf("    }\n");
			}
                        break;
                }

                case RISCV_INS_MULW: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int rs1 = reg_to_index(riscv->operands[1].reg);
                        int rs2 = reg_to_index(riscv->operands[2].reg);
                        //0 reg should not be added into
                        if (rd != 0) printf("    cpu.regs[%d] = (uint64_t)(uint32_t)(cpu.regs[%d] * cpu.regs[%d]);\n", rd, rs1, rs2);
			if (trusted) {
				printf("    {\n");
				printf("        trace_val(cpu.regs[%d]);\n", rd);
				printf("    }\n");
			}
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
        		//dont need target for these as they are static
			if (trusted) {
				printf("    {\n");
				printf("        int taken = (cpu.regs[%d] == cpu.regs[%d]);\n", rs1, rs2);	
				printf("        taken ? trace_branch_taken(0x%lx) : trace_branch_not_taken();\n", target);
				printf("        if (taken) goto L_0x%lx;\n", target);
				printf("    }\n");
			} else {
				printf("    if (cpu.regs[%d] == cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			}

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
			if (trusted) {
				printf("    {\n");
				printf("        int taken = (cpu.regs[%d] != cpu.regs[%d]);\n", rs1, rs2);	
				printf("        taken ? trace_branch_taken(0x%lx) : trace_branch_not_taken();\n", target);
				printf("        if (taken) goto L_0x%lx;\n", target);
				printf("    }\n");
			} else {
				printf("    if (cpu.regs[%d] != cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			}
                        break;
                }


		//branch greater than or equal to unsigned
                case RISCV_INS_BGEU: {
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
			if (trusted) {
				printf("    {\n");
				printf("        int taken = ((uint64_t)cpu.regs[%d] >= (uint64_t)cpu.regs[%d]);\n", rs1, rs2);	
				printf("        taken ? trace_branch_taken(0x%lx) : trace_branch_not_taken();\n", target);
				printf("        if (taken) goto L_0x%lx;\n", target);
				printf("    }\n");
			} else {
				printf("    if ((uint64_t)cpu.regs[%d] >= (uint64_t)cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			}
                        break;
                }


		//branch greater than or equal to
                case RISCV_INS_BGE: {
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
			if (trusted) {
				printf("    {\n");
				printf("        int taken = (cpu.regs[%d] >= cpu.regs[%d]);\n", rs1, rs2);	
				printf("        taken ? trace_branch_taken(0x%lx) : trace_branch_not_taken();\n", target);
				printf("        if (taken) goto L_0x%lx;\n", target);
				printf("    }\n");
			} else {
				printf("    if (cpu.regs[%d] >= cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			}
                        break;
                }

		//branch less than unsigned
                case RISCV_INS_BLTU: {
                        int rs1 = reg_to_index(riscv->operands[0].reg);
                        int rs2 = reg_to_index(riscv->operands[1].reg);
                        uint64_t target = get_branch_target(insn);
			if (trusted) {
				printf("    {\n");
				printf("        int taken = ((uint64_t)cpu.regs[%d] < (uint64_t)cpu.regs[%d]);\n", rs1, rs2);	
				printf("        taken ? trace_branch_taken(0x%lx) : trace_branch_not_taken();\n", target);
				printf("        if (taken) goto L_0x%lx;\n", target);
				printf("    }\n");
			} else {
                        	printf("    if ((uint64_t)cpu.regs[%d] < (uint64_t)cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			}
                        break;
                }

                //branch less than signed
                case RISCV_INS_BLT: {
                        int rs1 = reg_to_index(riscv->operands[0].reg);
                        int rs2 = reg_to_index(riscv->operands[1].reg);
                        uint64_t target = get_branch_target(insn);
			if (trusted) {
				printf("    {\n");
				printf("        int taken = (cpu.regs[%d] < cpu.regs[%d]);\n", rs1, rs2);	
				printf("        taken ? trace_branch_taken(0x%lx) : trace_branch_not_taken();\n", target);
				printf("        if (taken) goto L_0x%lx;\n", target);
				printf("    }\n");
			} else {
                        	printf("    if (cpu.regs[%d] < cpu.regs[%d]) goto L_0x%lx;\n", rs1, rs2, target);
			}
                        break;
                }

                //unconditional jumps
                case RISCV_INS_JAL: {
                        //TODO: add linking mechanic for jump and link when we need it (not yet for factorial)
                        if (riscv->op_count == 1) {
                                //just a regular jump (no link)
                                uint64_t target = get_branch_target(insn);
				if (trusted) {
					printf("    {\n");
					printf("        trace_branch_taken(0x%lx);\n", target);
					printf("    };\n");
				}
                                printf("    goto L_0x%lx;\n", target);
                        }
                        break;
                }

                //store double instruction
                case RISCV_INS_SD: {
                        int rs2 = reg_to_index(riscv->operands[0].reg);
                        int base_reg = reg_to_index(riscv->operands[1].mem.base);
                        int64_t offset = riscv->operands[1].mem.disp;

			//for stores and loads, result_value will be the value and target_pc will hold the memory location
			if (trusted) {
				printf("    {\n");
				printf("        uint64_t addr = cpu.regs[%d] + %ld;\n", base_reg, offset);
				printf("        *(int64_t*)(memory + addr) = cpu.regs[%d];\n", rs2); //actual instr
				printf("        trace_mem(addr, cpu.regs[%d]);\n", rs2);
				printf("    }\n");
			} else {
                        	printf("    *(int64_t*)(memory + cpu.regs[%d] + %ld) = cpu.regs[%d];\n", base_reg, offset, rs2);
			}
                        break;
                }

                //store word instruction
                case RISCV_INS_SW: {
                        int rs2 = reg_to_index(riscv->operands[0].reg);
                        int base_reg = reg_to_index(riscv->operands[1].mem.base);
                        int64_t offset = riscv->operands[1].mem.disp;

			//for stores and loads, result_value will be the value and target_pc will hold the memory location
			if (trusted) {
				printf("    {\n");
				printf("        uint64_t addr = cpu.regs[%d] + %ld;\n", base_reg, offset);
				printf("        *(int32_t*)(memory + addr) = (int32_t)cpu.regs[%d];\n", rs2); //actual instr
				printf("        trace_mem(addr, (uint64_t)(int32_t)cpu.regs[%d]);\n", rs2);
				printf("    }\n");
			} else {
                        	printf("    *(int32_t*)(memory + cpu.regs[%d] + %ld) = (int32_t)(cpu.regs[%d]);\n", base_reg, offset, rs2);
			}
                        break;
                }

                //load double instruction
                case RISCV_INS_LD: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int base_reg = reg_to_index(riscv->operands[1].mem.base);
                        int64_t offset = riscv->operands[1].mem.disp;
                        //dont ever load to reg 0
			if (rd != 0) {
				//for stores and loads, result_value will be the value and target_pc will hold the memory location
				if (trusted) {
					printf("    {\n");
					printf("        uint64_t addr = cpu.regs[%d] + %ld;\n", base_reg, offset);
					printf("        cpu.regs[%d] = *(int64_t*)(memory + addr);\n", rd); //actual instr
					printf("        trace_mem(addr, cpu.regs[%d]);\n", rd);
					printf("    }\n");
				} else {
                        		printf("    cpu.regs[%d] = *(int64_t*)(memory + cpu.regs[%d] + %ld);\n", rd, base_reg, offset);
				}
			}
                        break;
                }

                //load word instruction
                case RISCV_INS_LW: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int base_reg = reg_to_index(riscv->operands[1].mem.base);
                        int64_t offset = riscv->operands[1].mem.disp;
                        //dont ever load to reg 0
			if (rd != 0) {
				//for stores and loads, result_value will be the value and target_pc will hold the memory location
				if (trusted) {
					printf("    {\n");
					printf("        uint64_t addr = cpu.regs[%d] + %ld;\n", base_reg, offset);
					printf("        cpu.regs[%d] = (int64_t)*(int32_t*)(memory + addr);\n", rd); //actual instr
					printf("        trace_mem(addr, cpu.regs[%d]);\n", rd);
					printf("    }\n");
				} else {
                        		printf("    cpu.regs[%d] = (int64_t)*(int32_t*)(memory + cpu.regs[%d] + %ld);\n", rd, base_reg, offset);
				}
			}
                        break;
                }

                //load word instruction unsigned
                case RISCV_INS_LWU: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int base_reg = reg_to_index(riscv->operands[1].mem.base);
                        int64_t offset = riscv->operands[1].mem.disp;
                        //dont ever load to reg 0
			if (rd != 0) {
				//for stores and loads, result_value will be the value and target_pc will hold the memory location
				if (trusted) {
					printf("    {\n");
					printf("        uint64_t addr = cpu.regs[%d] + %ld;\n", base_reg, offset);
					printf("        cpu.regs[%d] = (int64_t)*(uint32_t*)(memory + addr);\n", rd); //actual instr
					printf("        trace_mem(addr, cpu.regs[%d]);\n", rd);
					printf("    }\n");
				} else {
                        		printf("    cpu.regs[%d] = (int64_t)*(uint32_t*)(memory + cpu.regs[%d] + %ld);\n", rd, base_reg, offset);
				}
			}
                        break;
                }

                case RISCV_INS_LUI: {
                        int rd = reg_to_index(riscv->operands[0].reg);
                        int64_t imm = riscv->operands[1].imm;
			if (rd != 0) {
				//for stores and loads, result_value will be the value and target_pc will hold the memory location
				//immediate stored in instruction so just send the value and flag
				if (trusted) {
					printf("    {\n");
					printf("        cpu.regs[%d] = (int64_t)(int32_t)(0x%lx << 12);\n", rd, imm); //actual instr
					printf("        trace_mem(addr, cpu.regs[%d]);\n", rd);
					printf("    }\n");
				} else {
                        		printf("    cpu.regs[%d] = (int64_t)(int32_t)(0x%lx << 12);\n", rd, imm);
				}
			}
                        break;
                }

		case RISCV_INS_AUIPC: {
			int rd = reg_to_index(riscv->operands[0].reg);
			//cast to 32 bit so it rolls over to negative, issue with printf before
			int64_t imm = (int32_t)riscv->operands[1].imm << 12;	
			uint64_t pc = insn->address;

			if (rd != 0) {
				printf("    cpu.regs[%d] = 0x%lxULL + %ldLL;\n", rd, pc, imm);
				// rd = current_pc + immediate
				if (trusted) {
					printf("    {\n");
					printf("        trace_val(cpu.regs[%d]);\n", rd);
					printf("    }\n");
				}
			}
			break;
		}


		case RISCV_INS_JALR: {
			if (!riscv->operands[0].reg && !riscv->operands[1].reg) {
				//ret instruction
				if (trusted) {
					printf("    {\n");
					printf("        trace_branch_taken(cpu.regs[1]);\n");
					printf("    }\n");
				}
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
	printf("//--CALL TO FUNCTION NAMED: %s ------------------\n", func_name.c_str());
	return  (func_name == "printf@plt" || func_name == "puts@plt");
}

void replace_function(std::string func_name) {
	if (func_name == "printf@plt") {

		printf("        // Library Call to printf (Interposed)\n");
		printf("        {\n");
		printf("            char* fmt = (char*)(memory + cpu.regs[10]);\n");
		printf("            printf(fmt, cpu.regs[11], cpu.regs[12], cpu.regs[13], cpu.regs[14]);\n");
		printf("            cpu.regs[10] = 0; \n");
		printf("        }\n");
	} else if (func_name == "puts@plt") {

		printf("        // Library Call to puts (Interposed)\n");
		printf("        {\n");
		printf("            char* str = (char*)(memory + cpu.regs[10]);\n");
		printf("            int ret = puts(str);\n");
		printf("            cpu.regs[10] = ret;\n");
		printf("        }\n");
	}

}

//print the function that acts as the functional eq of the text section
void print_run_cpu(csh handle, const uint8_t *code_ptr, size_t code_size, uint64_t address, cs_insn *insn, uint64_t main_addr, std::set<uint64_t>& targets, std::map<uint64_t, SymbolInfo>& symbols) {
	//set up the stack and return address from main to stub
	printf("int64_t run_cpu() {\n");
	printf("    RegisterFile cpu = {0};\n");
	printf("    cpu.regs[2] = 0x7FFFFFF0;\n");
	printf("    cpu.regs[1] = (int64_t)&&L_RETFROMMAIN;\n");
	printf("    goto L_0x%lx;\n", main_addr);


	while (code_size > 0) {
		//skip compiler generated bookkeeping functions, we handle setup ourselves and will not
		//actually be linking to the stdlib the binary thinks		
		if (symbols.count(address)) {
			SymbolInfo info = symbols[address];
			
			//set the mode and then send if 
			if (info.name.rfind("TGtrusted_", 0) == 0 || info.name == "main") {
				trusted = true;
				printf("//----------IN TRUSTED SPACE----------\n");
			} else {
				trusted = false;
				printf("//----------IN UNTRUSTED SPACE----------\n");
			}	

			if (info.name == "_start" || info.name == "deregister_tm_clones" || 
			    info.name == "register_tm_clones" || info.name == "__do_global_dtors_aux" || 
			    info.name == "frame_dummy" || info.name == "load_gp"  || info.name == "$x") {
			    
				// 1. Find the next symbol in the map to determine how much to skip
				auto it = symbols.find(address);
				it++; // Move to next symbol
			    
			    	uint64_t next_addr;
			    	if (it != symbols.end()) {
					next_addr = it->first;
			    	} else {
					// If there is no next symbol, skip to the end of the section
					next_addr = address + code_size; 
			    	}

			    	uint64_t actual_skip = next_addr - address;
			    
			    	printf("// Skipping compiler-generated function: %s (%lu bytes)\n", info.name.c_str(), actual_skip);
			    
			    	address += actual_skip;
			    	code_ptr += actual_skip;
			    	code_size -= actual_skip;
			    	continue; 
			}
			
			printf("\n// --- Function: %s ---\n", info.name.c_str());
	    	}			

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
				
						
					if (find_iterator != symbols.end() && is_replaceable_function(find_iterator->second.name.c_str())) {
						//symbol exists and is one of our replaceable functions
						//TODO: make call to general function that contains all possible replacable functions
						//and replaces with appropriate call
						
						
						replace_function(find_iterator->second.name.c_str());

		
						//this will become a generic function for replacing target lib functions	
					} else {
						//doesn't exist, do regular logic, function in in translated C land

						printf("    //AUIPC + JALR -> Static Goto\n");
						printf("    cpu.regs[1] = (int64_t)&&L_0x%lx;\n", ret_addr);
						//send to sentry for function call jump
						//we need to send the target address for this one cuz its calculated at runtime
						if (trusted) {
							printf("    {\n");
							printf("        trace_branch_taken(0x%lx);\n", target);
							printf("        maybe_flush_buffer();\n");
							printf("    }\n");
						}
						printf("    goto L_0x%lx;\n", target);
					}
		

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
		//PLACE ADITIONAL INSTRUMENTATION HERE (EVERY INSTRUCTION EXECUTES BESIDES FUNCTION CALL JUMPS)
		//TODO:addition instrumentation
		if (trusted) {
			printf("//----------TRUSTED INSTRUCTION----------\n");
		}
		printf("    maybe_flush_buffer();\n");
	}
	
	//label pointer to this label will be pushed onto stack
	//at RIP before entering main, if we see it in a ret, jump here	
	printf("\nL_RETFROMMAIN:\n");
	printf("    flush_buffer_final();\n");
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
	std::set<uint64_t> targets = collect_branch_targets(handle, text_section_ptr, text_size, text_section_addr, insn);
	//collect sybols and plt stubs for function replacement and compiler generated function skipping in run_cpu
	std::map<uint64_t, SymbolInfo> symbols = collect_symbols(elf_buffer.data());

	//test symbols (print as comments in file)
	//TODO: delete
	for (const auto& [addr, obj] : symbols) {
        	std::cout <<  "//" << std::hex << addr << ": " << obj.name << "\n";
    	}
	
	//print the file (will go to stdout, needs to be captured)
	print_header();
	print_init_memory();
	print_run_cpu(handle, text_section_ptr, text_size, text_section_addr, insn, entry_point, targets, symbols);
	print_main();
	return 0;
}

