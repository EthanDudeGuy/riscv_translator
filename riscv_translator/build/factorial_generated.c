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
    if (!read(fd, phdrs, sizeof(Elf64_Phdr) * ehdr.e_phnum)) {

        fprintf(stderr, "Error: failed to read program headers\n"); exit(1);
    }

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
    cpu.regs[1] = (int64_t)&&L_RETFROMMAIN;
    goto L_0x11190;
L_0x11190:
    // addi sp, sp, -0x30
    cpu.regs[2] = cpu.regs[2] + -48;
    // sd ra, 0x28(sp)
    *(int64_t*)(memory + cpu.regs[2] + 40) = cpu.regs[1];
    // sd s0, 0x20(sp)
    *(int64_t*)(memory + cpu.regs[2] + 32) = cpu.regs[8];
    // addi s0, sp, 0x30
    cpu.regs[8] = cpu.regs[2] + 48;
    // mv a2, zero
    cpu.regs[12] = cpu.regs[0] + 0;
    // sw a2, -0x14(s0)
    *(int32_t*)(memory + cpu.regs[8] + -20) = (int32_t)(cpu.regs[12]);
    // sw a0, -0x18(s0)
    *(int32_t*)(memory + cpu.regs[8] + -24) = (int32_t)(cpu.regs[10]);
    // sd a1, -0x20(s0)
    *(int64_t*)(memory + cpu.regs[8] + -32) = cpu.regs[11];
    // addi a0, zero, 1
    cpu.regs[10] = cpu.regs[0] + 1;
    // sd a0, -0x28(s0)
    *(int64_t*)(memory + cpu.regs[8] + -40) = cpu.regs[10];
    // lui a0, 0x12
    cpu.regs[10] = (int64_t)(int32_t)(0x12 << 12);
    // lw a0, 0x250(a0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[10] + 592);
    // beqz a0, 0x1c
    if (cpu.regs[10] == cpu.regs[0]) goto L_0x111dc;
    // j 4
    goto L_0x111c8;
L_0x111c8:
    // lui a0, 0x12
    cpu.regs[10] = (int64_t)(int32_t)(0x12 << 12);
    // lw a0, 0x250(a0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[10] + 592);
    // addi a1, zero, 1
    cpu.regs[11] = cpu.regs[0] + 1;
    // bne a0, a1, 0x14
    if (cpu.regs[10] != cpu.regs[11]) goto L_0x111e8;
    // j 4
    goto L_0x111dc;
L_0x111dc:
    // addi a0, zero, 1
    cpu.regs[10] = cpu.regs[0] + 1;
    // sw a0, -0x14(s0)
    *(int32_t*)(memory + cpu.regs[8] + -20) = (int32_t)(cpu.regs[10]);
    // j 0x54
    goto L_0x11238;
L_0x111e8:
    // addi a0, zero, 2
    cpu.regs[10] = cpu.regs[0] + 2;
    // sw a0, -0x2c(s0)
    *(int32_t*)(memory + cpu.regs[8] + -44) = (int32_t)(cpu.regs[10]);
    // j 4
    goto L_0x111f4;
L_0x111f4:
    // lw a1, -0x2c(s0)
    cpu.regs[11] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -44);
    // lui a0, 0x12
    cpu.regs[10] = (int64_t)(int32_t)(0x12 << 12);
    // lw a0, 0x250(a0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[10] + 592);
    // bltu a0, a1, 0x2c
    if ((uint64_t)cpu.regs[10] < (uint64_t)cpu.regs[11]) goto L_0x1122c;
    // j 4
    goto L_0x11208;
L_0x11208:
    // lwu a1, -0x2c(s0)
    cpu.regs[11] = (int64_t)*(uint32_t*)(memory + cpu.regs[8] + -44);
    // ld a0, -0x28(s0)
    cpu.regs[10] = *(int64_t*)(memory + cpu.regs[8] + -40);
    // mul a0, a0, a1
    cpu.regs[10] = cpu.regs[10] * cpu.regs[11];
    // sd a0, -0x28(s0)
    *(int64_t*)(memory + cpu.regs[8] + -40) = cpu.regs[10];
    // j 4
    goto L_0x1121c;
L_0x1121c:
    // lw a0, -0x2c(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -44);
    // addiw a0, a0, 1
    cpu.regs[10] = (int64_t)(int32_t)(cpu.regs[10] + 1);
    // sw a0, -0x2c(s0)
    *(int32_t*)(memory + cpu.regs[8] + -44) = (int32_t)(cpu.regs[10]);
    // j -0x34
    goto L_0x111f4;
L_0x1122c:
    // ld a0, -0x28(s0)
    cpu.regs[10] = *(int64_t*)(memory + cpu.regs[8] + -40);
    // sw a0, -0x14(s0)
    *(int32_t*)(memory + cpu.regs[8] + -20) = (int32_t)(cpu.regs[10]);
    // j 4
    goto L_0x11238;
L_0x11238:
    // lw a0, -0x14(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -20);
    // addi sp, s0, -0x30
    cpu.regs[2] = cpu.regs[8] + -48;
    // ld ra, 0x28(sp)
    cpu.regs[1] = *(int64_t*)(memory + cpu.regs[2] + 40);
    // ld s0, 0x20(sp)
    cpu.regs[8] = *(int64_t*)(memory + cpu.regs[2] + 32);
    // addi sp, sp, 0x30
    cpu.regs[2] = cpu.regs[2] + 48;
    // ret 
    goto *(void *)cpu.regs[1];

L_RETFROMMAIN:
    return cpu.regs[10];
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("Usage: %s <original_elf>\n", argv[0]); return 1; }
    int64_t retval = 0;
    init_memory(argv[1]);
    retval = run_cpu();
    return retval;
}
