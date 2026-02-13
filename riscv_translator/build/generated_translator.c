#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

// Global RV64 State
int64_t x[32] = {0};
uint8_t* memory = NULL;
uint64_t starting_address = 0;

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

    starting_address = ehdr.e_entry;
    printf("[Loader] Entry point found: 0x%08lx\n", starting_address);

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
void run_cpu(uint64_t entry_point) {
    printf("%lx\n", entry_point);
    // addi sp, sp, -0x20
    // sd ra, 0x18(sp)
    // sd s0, 0x10(sp)
    // addi s0, sp, 0x20
    // sw a0, -0x14(s0)
    // lw a0, -0x14(s0)
    // lui a1, 0x4bda1
    // addi a1, a1, 0x2f7
    // mul a1, a0, a1
    // srli a2, a1, 0x3f
    // srai a1, a1, 0x23
    // addw a1, a1, a2
    // addi a2, zero, 0x1b
    // mulw a1, a1, a2
    // subw a0, a0, a1
    // addi sp, s0, -0x20
    // ld ra, 0x18(sp)
    // ld s0, 0x10(sp)
    // addi sp, sp, 0x20
    // ret 
    // addi sp, sp, -0x30
    // sd ra, 0x28(sp)
    // sd s0, 0x20(sp)
    // addi s0, sp, 0x30
    // mv a0, zero
    // sd a0, -0x30(s0)
    // sw a0, -0x14(s0)
    // addi a0, zero, -1
    // srli a0, a0, 0x20
    // sd a0, -0x20(s0)
    // Custom Instruction: 0x100b0000200b
    // Custom Instruction: 0xfe0435030000100b
    // ld a0, -0x20(s0)
    // Custom Instruction: 0x400b0005300b
    // Custom Instruction: 0xfca43c230000400b
    // sd a0, -0x28(s0)
    // Custom Instruction: 0xfd8425030000500b
    // lw a0, -0x28(s0)
    // auipc ra, 0
    // jalr ra
    // ld a0, -0x30(s0)
    // addi sp, s0, -0x30
    // ld ra, 0x28(sp)
    // ld s0, 0x20(sp)
    // addi sp, sp, 0x30
    // ret 
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("Usage: %s <original_elf>\n", argv[0]); return 1; }
    init_memory(argv[1]);
    // The entry point will be passed to your run_cpu function
    // We'll calculate this during translation
    run_cpu(starting_address);
    return 0;
}
