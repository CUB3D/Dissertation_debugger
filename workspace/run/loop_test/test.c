#include <string.h>
#include <stdbool.h>
#include <stdio.h>

int main() {
    while(1) {
        sleep(1);
        fprintf(stderr, "Still here\n");
    }

    return 0;
}
