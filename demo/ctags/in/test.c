#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

bool check_password(char* test1, size_t test1_len, char* test2) {
    size_t ll = test1_len;
    for(int i = 0; i < ll; i++) {
        if (test1[i] != test2[i]) {
            return false;
        }
    }
    return true;
}

int main(int argc, char** argv) {
    if(argc < 2) {
        printf("Missing arg, <password-file>\n");
        return -1;
    }
    FILE* f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    char* buffer = malloc(len);
    rewind(f);
    fread(buffer, len, 1, f);

    printf("Read %d bytes\n", len);

    char* test1 = "HelloWorld";
    if (check_password(test1, strlen(test1), buffer)) {
        printf("Password correct\n");
    } else {
        printf("Password incorrect\n");
    }
    free(buffer);

    return 0;
}
