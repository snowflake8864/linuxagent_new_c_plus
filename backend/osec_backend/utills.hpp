#include <stdio.h>
int string_include(const char* s, const char* tmpl)
{
    while (*tmpl) {
        if (*tmpl != *s) {
            return 0;
        }

        tmpl++;
        s++;
    }

    return 1;
}