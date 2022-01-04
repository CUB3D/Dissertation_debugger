#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

bool check_password(char* test1, char* test2) {
    for(int i = 0; i < strlen(test1); i++) {
        if (test1[i] != test2[i]) {
            return false;
        }
    }
    return true;
}

int main() {
    char* test1 = "HelloWorld";
    char* test2 = malloc(100);;
    
    for(int i =0; i < strlen(test1); i++) {
        test2[i] = test1[i];
    }

    if (check_password(test1, test2)) {
        printf("Password correct\n");
    } else {
        printf("Password incorrect\n");
    }

    return 0;
}
