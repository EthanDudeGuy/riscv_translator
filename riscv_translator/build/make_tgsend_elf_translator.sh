make
./elf_translator ~/llvm-project/testexamples/builtins.elf > builtins_generated.c
gcc -O2 -g -o builtins_generated builtins_generated.c
