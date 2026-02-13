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
    // addi sp, sp, -0x30  is target: 0
    // sd ra, 0x28(sp)  is target: 0
    // sd s0, 0x20(sp)  is target: 0
    // addi s0, sp, 0x30  is target: 0
    // mv a2, zero  is target: 0
    // sw a2, -0x14(s0)  is target: 0
    // sw a0, -0x18(s0)  is target: 0
    // sd a1, -0x20(s0)  is target: 0
    // addi a0, zero, 1  is target: 0
    // sd a0, -0x28(s0)  is target: 0
    // addi a0, zero, 5  is target: 0
    // sw a0, -0x2c(s0)  is target: 0
    // lw a0, -0x2c(s0)  is target: 0
    // beqz a0, 0x18  is target: 0
    // j 4  is target: 0
L_0x11194:
    // lw a0, -0x2c(s0)  is target: 1
    // addi a1, zero, 1  is target: 0
    // bne a0, a1, 0x14  is target: 0
    // j 4  is target: 0
L_0x111a4:
    // addi a0, zero, 1  is target: 1
    // sw a0, -0x14(s0)  is target: 0
    // j 0x50  is target: 0
L_0x111b0:
    // addi a0, zero, 2  is target: 1
    // sw a0, -0x30(s0)  is target: 0
    // j 4  is target: 0
L_0x111bc:
    // lw a1, -0x30(s0)  is target: 1
    // lw a0, -0x2c(s0)  is target: 0
    // bltu a0, a1, 0x2c  is target: 0
    // j 4  is target: 0
L_0x111cc:
    // lwu a1, -0x30(s0)  is target: 1
    // ld a0, -0x28(s0)  is target: 0
    // mul a0, a0, a1  is target: 0
    // sd a0, -0x28(s0)  is target: 0
    // j 4  is target: 0
L_0x111e0:
    // lw a0, -0x30(s0)  is target: 1
    // addiw a0, a0, 1  is target: 0
    // sw a0, -0x30(s0)  is target: 0
    // j -0x30  is target: 0
L_0x111f0:
    // ld a0, -0x28(s0)  is target: 1
    // sw a0, -0x14(s0)  is target: 0
    // j 4  is target: 0
L_0x111fc:
    // lw a0, -0x14(s0)  is target: 1
    // addi sp, s0, -0x30  is target: 0
    // ld ra, 0x28(sp)  is target: 0
    // ld s0, 0x20(sp)  is target: 0
    // addi sp, sp, 0x30  is target: 0
    // ret   is target: 0
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("Usage: %s <original_elf>\n", argv[0]); return 1; }
    init_memory(argv[1]);
    // The entry point will be passed to your run_cpu function
    // We'll calculate this during translation
    run_cpu(starting_address);
    return 0;
}
