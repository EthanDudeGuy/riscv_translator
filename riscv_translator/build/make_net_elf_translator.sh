make
./elf_translator ~/llvm-project/testexamples/testnet.elf > net_generated.c
gcc -O2 -g -o net_generated net_generated.c
