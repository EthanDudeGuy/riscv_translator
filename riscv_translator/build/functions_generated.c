//71: $d
//304: __abi_tag
//598: _IO_stdin_used
//5af: $d
//5e8: __FRAME_END__
//610: $d
//800: __global_pointer$
//16a4: _start
//16ce: load_gp
//16da: $x
//16fc: register_tm_clones
//1728: __do_global_dtors_aux
//1766: frame_dummy
//1770: addemup
//17a8: factorial
//1850: main
//1900: __libc_start_main@plt
//1910: printf@plt
//2928: __do_global_dtors_aux_fini_array_entry
//2930: __frame_dummy_init_array_entry
//2938: _DYNAMIC
//3b10: __data_start
//3b18: global
//3b20: __TMC_END__
//3b40: completed.0
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
    goto L_0x1850;
//----------IN UNTRUSTED SPACE----------
// Skipping compiler-generated function: _start (42 bytes)
//----------IN UNTRUSTED SPACE----------
// Skipping compiler-generated function: load_gp (12 bytes)
//----------IN UNTRUSTED SPACE----------
// Skipping compiler-generated function: $x (34 bytes)
//----------IN UNTRUSTED SPACE----------
// Skipping compiler-generated function: register_tm_clones (44 bytes)
//----------IN UNTRUSTED SPACE----------
// Skipping compiler-generated function: __do_global_dtors_aux (62 bytes)
//----------IN UNTRUSTED SPACE----------
// Skipping compiler-generated function: frame_dummy (10 bytes)
//----------IN UNTRUSTED SPACE----------

// --- Function: addemup ---
L_0x1770:
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
    goto *(void *)cpu.regs[1];
//----------IN UNTRUSTED SPACE----------

// --- Function: factorial ---
L_0x17a8:
    // addi sp, sp, -0x30
    cpu.regs[2] = cpu.regs[2] + -48;
    // sd ra, 0x28(sp)
    *(int64_t*)(memory + cpu.regs[2] + 40) = cpu.regs[1];
    // sd s0, 0x20(sp)
    *(int64_t*)(memory + cpu.regs[2] + 32) = cpu.regs[8];
    // addi s0, sp, 0x30
    cpu.regs[8] = cpu.regs[2] + 48;
    // sw a0, -0x18(s0)
    *(int32_t*)(memory + cpu.regs[8] + -24) = (int32_t)(cpu.regs[10]);
    // addi a0, zero, 1
    cpu.regs[10] = cpu.regs[0] + 1;
    // sd a0, -0x20(s0)
    *(int64_t*)(memory + cpu.regs[8] + -32) = cpu.regs[10];
    // lw a0, -0x18(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -24);
    // beqz a0, 0x18
    if (cpu.regs[10] == cpu.regs[0]) goto L_0x17e0;
    // j 4
    goto L_0x17d0;
L_0x17d0:
    // lw a0, -0x18(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -24);
    // addi a1, zero, 1
    cpu.regs[11] = cpu.regs[0] + 1;
    // bne a0, a1, 0x14
    if (cpu.regs[10] != cpu.regs[11]) goto L_0x17ec;
    // j 4
    goto L_0x17e0;
L_0x17e0:
    // addi a0, zero, 1
    cpu.regs[10] = cpu.regs[0] + 1;
    // sw a0, -0x14(s0)
    *(int32_t*)(memory + cpu.regs[8] + -20) = (int32_t)(cpu.regs[10]);
    // j 0x50
    goto L_0x1838;
L_0x17ec:
    // addi a0, zero, 2
    cpu.regs[10] = cpu.regs[0] + 2;
    // sw a0, -0x24(s0)
    *(int32_t*)(memory + cpu.regs[8] + -36) = (int32_t)(cpu.regs[10]);
    // j 4
    goto L_0x17f8;
L_0x17f8:
    // lw a1, -0x24(s0)
    cpu.regs[11] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -36);
    // lw a0, -0x18(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -24);
    // bltu a0, a1, 0x2c
    if ((uint64_t)cpu.regs[10] < (uint64_t)cpu.regs[11]) goto L_0x182c;
    // j 4
    goto L_0x1808;
L_0x1808:
    // lwu a1, -0x24(s0)
    cpu.regs[11] = (int64_t)*(uint32_t*)(memory + cpu.regs[8] + -36);
    // ld a0, -0x20(s0)
    cpu.regs[10] = *(int64_t*)(memory + cpu.regs[8] + -32);
    // mul a0, a0, a1
    cpu.regs[10] = cpu.regs[10] * cpu.regs[11];
    // sd a0, -0x20(s0)
    *(int64_t*)(memory + cpu.regs[8] + -32) = cpu.regs[10];
    // j 4
    goto L_0x181c;
L_0x181c:
    // lw a0, -0x24(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -36);
    // addiw a0, a0, 1
    cpu.regs[10] = (int64_t)(int32_t)(cpu.regs[10] + 1);
    // sw a0, -0x24(s0)
    *(int32_t*)(memory + cpu.regs[8] + -36) = (int32_t)(cpu.regs[10]);
    // j -0x30
    goto L_0x17f8;
L_0x182c:
    // ld a0, -0x20(s0)
    cpu.regs[10] = *(int64_t*)(memory + cpu.regs[8] + -32);
    // sw a0, -0x14(s0)
    *(int32_t*)(memory + cpu.regs[8] + -20) = (int32_t)(cpu.regs[10]);
    // j 4
    goto L_0x1838;
L_0x1838:
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
//----------IN TRUSTED SPACE----------

// --- Function: main ---
L_0x1850:
    // addi sp, sp, -0x30
    cpu.regs[2] = cpu.regs[2] + -48;
//----------TRUSTED INSTRUCTION----------
    // sd ra, 0x28(sp)
    *(int64_t*)(memory + cpu.regs[2] + 40) = cpu.regs[1];
//----------TRUSTED INSTRUCTION----------
    // sd s0, 0x20(sp)
    *(int64_t*)(memory + cpu.regs[2] + 32) = cpu.regs[8];
//----------TRUSTED INSTRUCTION----------
    // addi s0, sp, 0x30
    cpu.regs[8] = cpu.regs[2] + 48;
//----------TRUSTED INSTRUCTION----------
    // mv a0, zero
    cpu.regs[10] = cpu.regs[0] + 0;
//----------TRUSTED INSTRUCTION----------
    // sw a0, -0x14(s0)
    *(int32_t*)(memory + cpu.regs[8] + -20) = (int32_t)(cpu.regs[10]);
//----------TRUSTED INSTRUCTION----------
    // auipc a0, 0xfffff
    cpu.regs[10] = 0x1868ULL + -4096LL;
//----------TRUSTED INSTRUCTION----------
    // addi a0, a0, -0x2b9
    cpu.regs[10] = cpu.regs[10] + -697;
//----------TRUSTED INSTRUCTION----------
//--CALL TO FUNCTION NAMED: printf@plt ------------------
        // Library Call to printf (Interposed)
        {
            char* fmt = (char*)(memory + cpu.regs[10]);
            printf(fmt, cpu.regs[11], cpu.regs[12], cpu.regs[13], cpu.regs[14]);
            fflush(stdout);
            cpu.regs[10] = 0; 
        }
L_0x1878:
    // addi a0, zero, 1
    cpu.regs[10] = cpu.regs[0] + 1;
//----------TRUSTED INSTRUCTION----------
    // sw a0, -0x18(s0)
    *(int32_t*)(memory + cpu.regs[8] + -24) = (int32_t)(cpu.regs[10]);
//----------TRUSTED INSTRUCTION----------
    // addi a0, zero, 2
    cpu.regs[10] = cpu.regs[0] + 2;
//----------TRUSTED INSTRUCTION----------
    // sw a0, -0x1c(s0)
    *(int32_t*)(memory + cpu.regs[8] + -28) = (int32_t)(cpu.regs[10]);
//----------TRUSTED INSTRUCTION----------
    // lw a0, -0x18(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -24);
//----------TRUSTED INSTRUCTION----------
    // auipc a1, 2
    cpu.regs[11] = 0x188cULL + 8192LL;
//----------TRUSTED INSTRUCTION----------
    // addi a1, a1, 0x28c
    cpu.regs[11] = cpu.regs[11] + 652;
//----------TRUSTED INSTRUCTION----------
    // lw a1, 0(a1)
    cpu.regs[11] = (int64_t)*(int32_t*)(memory + cpu.regs[11] + 0);
//----------TRUSTED INSTRUCTION----------
//--CALL TO FUNCTION NAMED: addemup ------------------
    //AUIPC + JALR -> Static Goto
    cpu.regs[1] = (int64_t)&&L_0x18a0;
    goto L_0x1770;
L_0x18a0:
    // sw a0, -0x20(s0)
    *(int32_t*)(memory + cpu.regs[8] + -32) = (int32_t)(cpu.regs[10]);
//----------TRUSTED INSTRUCTION----------
    // lw a0, -0x20(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -32);
//----------TRUSTED INSTRUCTION----------
//--CALL TO FUNCTION NAMED: factorial ------------------
    //AUIPC + JALR -> Static Goto
    cpu.regs[1] = (int64_t)&&L_0x18b0;
    goto L_0x17a8;
L_0x18b0:
    // sw a0, -0x24(s0)
    *(int32_t*)(memory + cpu.regs[8] + -36) = (int32_t)(cpu.regs[10]);
//----------TRUSTED INSTRUCTION----------
    // lw a1, -0x24(s0)
    cpu.regs[11] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -36);
//----------TRUSTED INSTRUCTION----------
    // auipc a0, 0xfffff
    cpu.regs[10] = 0x18b8ULL + -4096LL;
//----------TRUSTED INSTRUCTION----------
    // addi a0, a0, -0x31c
    cpu.regs[10] = cpu.regs[10] + -796;
//----------TRUSTED INSTRUCTION----------
//--CALL TO FUNCTION NAMED: printf@plt ------------------
        // Library Call to printf (Interposed)
        {
            char* fmt = (char*)(memory + cpu.regs[10]);
            printf(fmt, cpu.regs[11], cpu.regs[12], cpu.regs[13], cpu.regs[14]);
            fflush(stdout);
            cpu.regs[10] = 0; 
        }
L_0x18c8:
    // lw a0, -0x24(s0)
    cpu.regs[10] = (int64_t)*(int32_t*)(memory + cpu.regs[8] + -36);
//----------TRUSTED INSTRUCTION----------
    // addi sp, s0, -0x30
    cpu.regs[2] = cpu.regs[8] + -48;
//----------TRUSTED INSTRUCTION----------
    // ld ra, 0x28(sp)
    cpu.regs[1] = *(int64_t*)(memory + cpu.regs[2] + 40);
//----------TRUSTED INSTRUCTION----------
    // ld s0, 0x20(sp)
    cpu.regs[8] = *(int64_t*)(memory + cpu.regs[2] + 32);
//----------TRUSTED INSTRUCTION----------
    // addi sp, sp, 0x30
    cpu.regs[2] = cpu.regs[2] + 48;
//----------TRUSTED INSTRUCTION----------
    // ret 
    goto *(void *)cpu.regs[1];
//----------TRUSTED INSTRUCTION----------

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
