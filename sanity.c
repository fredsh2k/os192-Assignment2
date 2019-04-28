//
// Created by fredsh2k on 4/24/19.
//
#include "types.h"

#include "user.h"
#include "kthread.h"
#include "tournament_tree.h"

#define STACK_SIZE 500

int m1 = 0;
int mutex_to_lock = 0;

void print_thread(){
    sleep(10);
    printf(1, "thread printing ... \n");
    kthread_exit();

}

void print_thread_id(){
    sleep(10);
    int res = kthread_id();
    if(res==-1) printf(1, "kthread_id Failed..\n");
    else printf(1, "kthread_id success :) ..... my id is: %d......\n", res);
    kthread_exit();

}

void func_dealloc(int mutex_id){
    sleep(10);
    int res = kthread_mutex_dealloc(mutex_id);
    if(res == -1) printf(1, "dealloc2 failed, as it should be\n");
    else printf(1, "dealloc1 succeed, not good\n");
    kthread_exit();

}


void func_unlock(int mutex_id){
    sleep(10);
    int res = kthread_mutex_unlock(mutex_id);
    if(res == -1) printf(1, "lock failed, the mutex is already unlocked as it should be\n");
    else printf(1, "lock succeed, not good\n");
    kthread_exit();
}


 #define THREAD_FUNC(name, mutex_id) \
    void name(){ \
        sleep(10); \
        int res = kthread_mutex_dealloc(mutex_id); \
        if(res == -1) printf(1, "dealloc2 failed, as it should be :)\n"); \
        else printf(1, "dealloc1 succeed, not good :(\n"); \
        kthread_exit(); \
    }

THREAD_FUNC(dealloc, m1)


void test_kthread_create(){
    void * stack = ((char *) malloc(STACK_SIZE * sizeof(char))) + STACK_SIZE;

    int tid = kthread_create(print_thread, stack);

    if(tid == -1) printf(1, "kthread_create failed :(\n");
    else printf(1, "kthread_create success :)\n");

//    kthread_join(tid);

}

void test_kthread_join(){
    void * stack = ((char *) malloc(STACK_SIZE * sizeof(char))) + STACK_SIZE;

    int tid = kthread_create(print_thread, stack);

    int res = kthread_join(tid);


    if(res == -1) printf(1, "kthread_join failed :(\n");
    else printf(1, "kthread_join success :)\n");


}

void test_kthread_id(){
    void * stack = ((char *) malloc(STACK_SIZE * sizeof(char))) + STACK_SIZE;

    for (int i=0; i< 5; i++){
        int tid = kthread_create(print_thread_id, stack);
        kthread_join(tid);
    }

}


void test_mutex_alloc(){
    printf(1, "Test kthread_mutex_alloc:\n");
    int res = kthread_mutex_alloc();

    if(res == -1) printf(1, "kthread_mutex_alloc failed :( \n");
    else printf(1, "kthread_mutex_alloc success :) \n");


}

void test_mutex_dealloc(){
    printf(1, "Test kthread_mutex_dealloc:\n");
    m1 = kthread_mutex_alloc();
    int d1 = kthread_mutex_dealloc(m1);

    void * stack = ((char *) malloc(STACK_SIZE * sizeof(char))) + STACK_SIZE;


    int tid = kthread_create(dealloc, stack);

    if(d1 == 0) printf(1, "dealloc1 succeed :) \n");
    else printf(1, "dealloc1 failed :( \n");

    kthread_join(tid);
}

void test_mutex_lock_unlock(){
    printf(1, "Test kthread_mutex_lock and unlock:\n");
    mutex_to_lock = kthread_mutex_alloc();

    int res = kthread_mutex_lock(mutex_to_lock);
    if(res == 0) printf(1, "lock succeed :) \n");
    else printf(1, "lock failed :( \n");

    res = kthread_mutex_unlock(mutex_to_lock);
    if(res == 0) printf(1, "unlock succeed :) \n");
    else printf(1, "unlock failed :( \n");

    void * stack = ((char *) malloc(STACK_SIZE * sizeof(char))) + STACK_SIZE;
    int tid = kthread_create(func_unlock, stack);
    kthread_join(tid);

}

void test_trnmnt_alloc(){
    int depth = 3;
    trnmnt_tree* tree = trnmnt_tree_alloc(depth);

    int size = tree->size;
    int expected_size = 7;

    if(size == expected_size) printf(1, "trnmnt_tree_alloc size OK :)\n");
    else printf(1, "trnmnt_tree_alloc size NOT OK :(\n");

    if(tree->depth == depth) printf(1, "trnmnt_tree_alloc depth OK :)\n");
    else printf(1, "trnmnt_tree_alloc depth NOT OK :(\n");


}

void test_trnmnt_dealloc(){
    int depth = 3;
    trnmnt_tree* tree = trnmnt_tree_alloc(depth);

    int res = trnmnt_tree_dealloc(tree);
    if(res == 0) printf(1, "trnmnt_tree_dealloc succeed :)\n");
    else printf(1, "trnmnt_tree_dealloc failed :(\n");

    res = trnmnt_tree_dealloc(tree);
    if(res == -1) printf(1, "trnmnt_tree_dealloc failed, as it should be :)\n");
    else printf(1, "trnmnt_tree_dealloc succeed, NOT OK :(\n");

}

// For test_trnmt_acquire
int shared_resource = 100;
trnmnt_tree* tree;


 #define THREAD_INCREASE(name, tree) \
    void name(){ \
    sleep(10); \
    trnmnt_tree_acquire(tree, 4); \
    shared_resource += 10; \
    trnmnt_tree_release(tree, 4); \
    kthread_exit(); \
    }

THREAD_INCREASE(increase_func, tree)

void test_trnmnt_acquire_release(){
    int depth = 3;
    tree = trnmnt_tree_alloc(depth);

    void * stack = ((char *) malloc(STACK_SIZE * sizeof(char))) + STACK_SIZE;
    kthread_create(increase_func, stack);

    trnmnt_tree_acquire(tree, 7);

    shared_resource += 10;

    trnmnt_tree_release(tree, 7);

    sleep(100);
    if(shared_resource == 120) printf(1, "trnmnt_acquire succeed :)\n");
    else printf(1, "trnmnbt acquire failed :(\n");

    printf(1, "should be: t7: 6 -> 2 -> 0\n");
    printf(1, "should be: t4: 5 -> 2 -> 0\n");


}


void test_task2_2(){
    printf(1, "Test Task2.2: CHECKING KTHREAD\n");
    printf(1, "----------------------------------------------------------------\n");
    test_kthread_create();
    test_kthread_join();
    test_kthread_id();
}



void test_task3_1(){
    printf(1, "Test Task3.1: CHECKING MUTEX\n");
    printf(1, "----------------------------------------------------------------\n");
    test_mutex_alloc();
    test_mutex_dealloc();
    test_mutex_lock_unlock();
}

void test_task3_2(){
    printf(1, "Test Task3.2: CHECKING TOURNAMENT TREE \n");
    printf(1, "----------------------------------------------------------------\n");
    test_trnmnt_alloc();
    test_trnmnt_dealloc();
    test_trnmnt_acquire_release();


}



int main(){

    printf(1, "Sanity started: \n");
    test_task2_2();
    test_task3_1();
    test_task3_2();

    exit();
}