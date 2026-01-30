#include <iostream>
#include <vector>
#include <fstream>
#include <capstone/capstone.h>

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

	
	//dissasemble binary
	const uint8_t *code_ptr = buffer.data();
	size_t code_size = buffer.size();
	uint64_t address = 0x1000; //starting address????
	cs_insn *insn = cs_malloc(handle);

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


