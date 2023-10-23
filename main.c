#include "utils.h"

static char* str = "Hello World!";
static char* str_2 = "Hello World 2!";

void other_empty_func() {
    puts(str);
    str[2] = 'h';
}

void empty_func() {
    puts(str);
}

int main() {
    setup_lookup_tables();
    function_t f = claim_function(empty_func);
    fix_function_addressing(&f);
    puts("Setup function!");

    empty_func();
    f.memory[14] += 8;
    empty_func();

    undo_lookup_tables();
    release_function(f);
    return 0;
}
