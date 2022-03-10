/*int is_odd2(int n) {
    return n % 2 == 1;
}

int is_odd(int n) {
    if (n == 1) {
        return 1;
    }
    if (n == 0) {
        return 0;
    }
    return is_odd(n - 2);
}

int is_prime(int n) {
    for (int i = 2; i < n; i++) {
        if (n%i == 0) {
            return 0;
        }
    }
    return 1;
}

int collatz_recur(int n) {
    int stopping_time = 1;
    if (n == 1) {
        return stopping_time;
    } if (n % 2 == 1) {
        stopping_time += collatz_recur(3*n + 1);
    } else {
        stopping_time += collatz_recur(n / 2);
    }
    return stopping_time;
}

int collatz_iter(int n) {
    int stopping_time = 0;
    while (n > 1) {
        if (n % 2 == 1) {
            n = 3*n + 1;
        } else {
            n = n / 2;
        }
        stopping_time++;
    }
    return stopping_time;
}*/

void loop() {
    int c = 0;

    volatile int x = 1;
    for (int i = 0; i < 1000000000; i++) {
        c += x;
    }
}

/*int prime_check() {
    long long int n = 2147483647;
        for (long long int i = 2; i < n; i++) {
            if (n%i == 0) {
                return 0;
            }
        }
        return 1;
}*/

int main() {
    return 10;
}
