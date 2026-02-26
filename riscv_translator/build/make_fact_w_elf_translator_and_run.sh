make
./elf_translator ~/llvm-project/testexamples/test_factorial.elf > factorial_generated.c
gcc -O2 -g -o factorial_generated factorial_generated.c
time ./factorial_generated ~/llvm-project/testexamples/test_factorial.elf
