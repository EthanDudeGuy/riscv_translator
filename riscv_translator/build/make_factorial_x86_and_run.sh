make
./translator ~/llvm-project/testexamples/test_fact.bin ~/llvm-project/testexamples/test_factorial.elf > factorial_generated.c
gcc factorial_generated.c -o x86equivalentof_test_factorial
./x86equivalentof_test_factorial ~/llvm-project/testexamples/test_factorial.elf
