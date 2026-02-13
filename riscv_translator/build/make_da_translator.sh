./translator ~/llvm-project/testexamples/test_enter_untrusted.bin > generated_translator.c
gcc ./generated_translator.c -o generated_translator_compiled
./generated_translator_compiled /home/trustguard/oldStuff/liberty/projects/emuchecker/fib/src/fib.ClangStraight.exe
