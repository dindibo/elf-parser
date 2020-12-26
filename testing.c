#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "elf-parser.h"
#include "elf-parser-main.h"

#define ASSERT(FUNC) assertFunction(#FUNC, FUNC)

void assertFunction(const char *testName, bool(*f)(void) ){
    printf("[TEST] %s --> ", testName);

    if((*f)()){
        puts("PASS");
    }
    else{
        puts("FAIL");
    }
}

bool assert_warper_32bit(){
    return is64Bit_warpper("./test/prog32bit") == false;
}

bool assert_warper_64bit(){
    return is64Bit_warpper("./test/prog64bit") == true;
}

#ifdef TEST
int main(){
    ASSERT(assert_warper_32bit);
    ASSERT(assert_warper_64bit);
}
#endif