#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>

_Atomic int counter;

void* thread1(void* vargp) {
    printf("Thread 1 pid = %d\n", getpid());
    while(1) {
        int expected = 0;
        if(atomic_compare_exchange_weak_explicit(&counter, &expected, 1, memory_order_seq_cst, memory_order_seq_cst)) {
            printf("Locked\n");
        }
//        printf("waiting for unlock\n");
        sleep(1);
    }

    return NULL;
}
void* thread2(void* vargp) {
    printf("Thread 2 pid = %d\n", getpid());
    while(1) {
        int expected = 1;
        if(atomic_compare_exchange_weak_explicit(&counter, &expected, 0, memory_order_seq_cst, memory_order_seq_cst)) {
            printf("Unlocked\n");
        }
//        printf("Waiting for lock\n");
        sleep(1);
    }
    return NULL;
}

int main() {
    printf("Main thread pid = %d\n", getpid());

    atomic_init(&counter, 0);

    pthread_t thread1_id;
    pthread_create(&thread1_id, NULL, thread1, NULL);
    pthread_t thread2_id;
    pthread_create(&thread2_id, NULL, thread2, NULL);

    printf("Created the threads\n");

    pthread_join(thread1_id, NULL);

    return 0;
}
