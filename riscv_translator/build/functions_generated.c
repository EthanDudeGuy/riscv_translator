#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

// Global RV64 State
typedef union {
    struct {
        int64_t zero, ra, sp, gp, tp, t0, t1, t2;
	int64_t s0, s1, a0, a1, a2, a3, a4, a5;
	int64_t a6, a7, s2, s3, s4, s5, s6, s7;
	int64_t s8, s9, s10, s11, t3, t4, t5, t6;
    };
    int64_t regs[32];

} RegisterFile;

uint8_t* memory = NULL;

void init_memory(const char* elf_path) {
    // 1. Reserve 4GB virtual address space
    memory = mmap(NULL, 0x100000000, PROT_READ | PROT_WRITE, 
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (memory == MAP_FAILED) { perror("mmap failed"); exit(1); }

    // 2. Open the RISC-V binary
    int fd = open(elf_path, O_RDONLY);
    if (fd < 0) { perror("open failed"); exit(1); }

    // 3. Read and Validate the ELF Header
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("read ehdr failed"); exit(1);
    }

    // Check Magic and Class
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1) {
        fprintf(stderr, "Error: '%s' is not a valid ELF file\n", elf_path);
        exit(1);
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Error: Expected 64-bit ELF\n"); exit(1);
    }

    // 4. Load Program Headers
    Elf64_Phdr* phdrs = malloc(sizeof(Elf64_Phdr) * ehdr.e_phnum);
    lseek(fd, ehdr.e_phoff, SEEK_SET);
    read(fd, phdrs, sizeof(Elf64_Phdr) * ehdr.e_phnum);

    // 5. Load PT_LOAD segments
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            lseek(fd, phdrs[i].p_offset, SEEK_SET);
            if (read(fd, &memory[phdrs[i].p_vaddr], phdrs[i].p_filesz) != phdrs[i].p_filesz) {
                fprintf(stderr, "Error loading segment %d\n", i); exit(1);
            }
            printf("[Loader] Loaded segment at 0x%08lx\n", phdrs[i].p_vaddr);
        }
    }
    free(phdrs);
    close(fd);
}

int64_t run_cpu() {
    RegisterFile cpu = {0};
    cpu.regs[2] = 0x7FFFFFF0;
    cpu.regs[1] = 0xDEADBEEF;
    //jump table (O(1) access, longer build time)
    static void* label_map[] = {
        &&L_0x11190,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_0x11200,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
        &&L_INVALID_TARGET,
    };
    uint64_t base_address = 0x11190ULL;

    goto L_0x111c8;
L_0x11190:
    // addi sp, sp, -0x20
    cpu.regs[2] = cpu.regs[2] + -32;
    // sd ra, 0x18(sp)
    *(int64_t*)(memory + cpu.regs[2] + 24) = cpu.regs[1];
    // sd s0, 0x10(sp)
    *(int64_t*)(memory + cpu.regs[2] + 16) = cpu.regs[8];
    // addi s0, sp, 0x20
    cpu.regs[8] = cpu.regs[2] + 32;
    // sw a0, -0x14(s0)
    *(int32_t*)(memory + cpu.regs[8] + -20) = (int32_t)(cpu.regs[10]);
    // sw a1, -0x18(s0)
    *(int32_t*)(memory + cpu.regs[8] + -24) = (int32_t)(cpu.regs[11]);
    // lw a0, -0x14(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -20);
    // lw a1, -0x18(s0)
    cpu.regs[11] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -24);
    // addw a0, a0, a1
    cpu.regs[10] = (int64_t)(int32_t)(cpu.regs[10] + cpu.regs[11]);
    // addi sp, s0, -0x20
    cpu.regs[2] = cpu.regs[8] + -32;
    // ld ra, 0x18(sp)
    cpu.regs[1] = *(int64_t*)(memory + cpu.regs[2] + 24);
    // ld s0, 0x10(sp)
    cpu.regs[8] = *(int64_t*)(memory + cpu.regs[2] + 16);
    // addi sp, sp, 0x20
    cpu.regs[2] = cpu.regs[2] + 32;
    // ret 
    if (cpu.regs[1] != 0xDEADBEEF) {
        goto *label_map[(cpu.regs[1] - base_address) / 4];
    } else {
        return cpu.a0;
    }
L_0x111c8:
    // addi sp, sp, -0x20
    cpu.regs[2] = cpu.regs[2] + -32;
    // sd ra, 0x18(sp)
    *(int64_t*)(memory + cpu.regs[2] + 24) = cpu.regs[1];
    // sd s0, 0x10(sp)
    *(int64_t*)(memory + cpu.regs[2] + 16) = cpu.regs[8];
    // addi s0, sp, 0x20
    cpu.regs[8] = cpu.regs[2] + 32;
    // mv a0, zero
    cpu.regs[10] = cpu.regs[0] + 0;
    // sw a0, -0x14(s0)
    *(int32_t*)(memory + cpu.regs[8] + -20) = (int32_t)(cpu.regs[10]);
    // addi a0, zero, 1
    cpu.regs[10] = cpu.regs[0] + 1;
    // sw a0, -0x18(s0)
    *(int32_t*)(memory + cpu.regs[8] + -24) = (int32_t)(cpu.regs[10]);
    // addi a0, zero, 2
    cpu.regs[10] = cpu.regs[0] + 2;
    // sw a0, -0x1c(s0)
    *(int32_t*)(memory + cpu.regs[8] + -28) = (int32_t)(cpu.regs[10]);
    // lw a0, -0x18(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -24);
    // lw a1, -0x1c(s0)
    cpu.regs[11] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -28);
    // auipc ra, 0
    cpu.regs[1] = 0x111f8ULL + 0LL;
    // jalr ra, ra, -0x68
    {
        uint64_t target = (cpu.regs[1] + -104) & ~1ULL;
        cpu.regs[1] = 0x11200ULL;
        uint64_t index = (target - base_address) / 4;
        goto *label_map[index];
    }
L_0x11200:
    // sw a0, -0x20(s0)
    *(int32_t*)(memory + cpu.regs[8] + -32) = (int32_t)(cpu.regs[10]);
    // lw a0, -0x20(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -32);
    // addi sp, s0, -0x20
    cpu.regs[2] = cpu.regs[8] + -32;
    // ld ra, 0x18(sp)
    cpu.regs[1] = *(int64_t*)(memory + cpu.regs[2] + 24);
    // ld s0, 0x10(sp)
    cpu.regs[8] = *(int64_t*)(memory + cpu.regs[2] + 16);
    // addi sp, sp, 0x20
    cpu.regs[2] = cpu.regs[2] + 32;
    // ret 
    if (cpu.regs[1] != 0xDEADBEEF) {
        goto *label_map[(cpu.regs[1] - base_address) / 4];
    } else {
        return cpu.a0;
    }


L_INVALID_TARGET:
    fprintf(stderr, "invalid target hit\n");
    exit(1);
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("Usage: %s <original_elf>\n", argv[0]); return 1; }
    int64_t retval = 0;
    init_memory(argv[1]);
    retval = run_cpu();
    return retval;
}
