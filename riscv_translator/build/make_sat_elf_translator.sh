make
./elf_translator ~/llvm-project/testexamples/sat_solve.elf > sat_generated.c
gcc -O2 -g -o sat_generated sat_generated.c
