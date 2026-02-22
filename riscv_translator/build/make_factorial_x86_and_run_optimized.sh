echo "[BUILDSCRIPT] building translator"
make
echo "[BUILDSCRIPT] running translator on riscv factorial(5) binary"
./translator ~/llvm-project/testexamples/test_fact.bin ~/llvm-project/testexamples/test_factorial.elf > factorial_generated.c
echo "[BUILDSCRIPT] compiling functionally equivalent C to x86 binary with system gcc"
gcc -O2 factorial_generated.c -o x86equivalentof_test_factorial
echo "[BUILDSCRIPT] running fucntionally equivalent x86 binary with origional RISCV elf as input"
./x86equivalentof_test_factorial ~/llvm-project/testexamples/test_factorial.elf
echo "x86 binary returned value: $?"
