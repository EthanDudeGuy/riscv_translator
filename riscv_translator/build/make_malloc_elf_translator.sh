make
./elf_translator ~/llvm-project/testexamples/malloc_test.elf > malloc_test_generated.c
gcc -O2 -g -o malloc_test_generated malloc_test_generated.c
