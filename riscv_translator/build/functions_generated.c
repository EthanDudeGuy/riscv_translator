int64_t run_cpu() {
    RegisterFile cpu = {0};
    cpu.regs[2] = 0x7FFFFFF0;
    goto L_0x70088;
L_0x70032:
    // addi sp, sp, -0x20
L_0x70036:
    // sd ra, 0x18(sp)
L_0x70040:
    // sd s0, 0x10(sp)
L_0x70044:
    // addi s0, sp, 0x20
L_0x70048:
    // sw a0, -0x14(s0)
L_0x70052:
    // sw a1, -0x18(s0)
L_0x70056:
    // lw a0, -0x14(s0)
L_0x70060:
    // lw a1, -0x18(s0)
L_0x70064:
    // addw a0, a0, a1
L_0x70068:
    // addi sp, s0, -0x20
L_0x70072:
    // ld ra, 0x18(sp)
L_0x70076:
    // ld s0, 0x10(sp)
L_0x70080:
    // addi sp, sp, 0x20
L_0x70084:
    // ret 
L_0x70088:
    // addi sp, sp, -0x20
L_0x70092:
    // sd ra, 0x18(sp)
L_0x70096:
    // sd s0, 0x10(sp)
L_0x70100:
    // addi s0, sp, 0x20
L_0x70104:
    // mv a0, zero
L_0x70108:
    // sw a0, -0x14(s0)
L_0x70112:
    // addi a0, zero, 1
L_0x70116:
    // sw a0, -0x18(s0)
L_0x70120:
    // addi a0, zero, 2
L_0x70124:
    // sw a0, -0x1c(s0)
L_0x70128:
    // lw a0, -0x18(s0)
L_0x70132:
    // lw a1, -0x1c(s0)
L_0x70136:
    // auipc ra, 0
L_0x70140:
    // jalr ra, ra, -0x68
L_0x70144:
    // sw a0, -0x20(s0)
L_0x70148:
    // lw a0, -0x20(s0)
L_0x70152:
    // addi sp, s0, -0x20
L_0x70156:
    // ld ra, 0x18(sp)
L_0x70160:
    // ld s0, 0x10(sp)
L_0x70164:
    // addi sp, sp, 0x20
L_0x70168:
    // ret 
    return cpu.a0;
}
