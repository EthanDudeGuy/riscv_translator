make
./elf_translator ~/llvm-project/testexamples/test_functions.elf > functions_generated.c
gcc -O2 -g -o functions_generated functions_generated.c
