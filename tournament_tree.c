#include "types.h"
#include "stat.h"
#include "fcntl.h"
#include "user.h"
#include "x86.h"

#include "tournament_tree.h"
#include "kthread.h"



/* Task 3.2 */

trnmnt_tree* trnmnt_tree_alloc(int depth){

    int size = (1 << depth) -1;  // the size of the tree
    trnmnt_tree *trnmnt = malloc(sizeof(trnmnt_tree));
    trnmnt->size = size;
    trnmnt->nodes = malloc(sizeof(int) * size);
    trnmnt->depth = depth;

//    struct kthread_mutex_t *m;
//    int num_of_free_mutex = 0;

//
//    for(int i = 0; i<MAX_MUTEXES; i++){
//        m = &mtable.mutexes[i];
//        if(!m->allocated) // if mutex is not yet allocated
//            num_of_free_mutex++;
//    }

//    if(num_of_free_mutex < size) {
//        return 0; // if there are not enough unallocated mutexes - error
//    }

    for(int i = 0; i < size; i++){
        int id = kthread_mutex_alloc();
        if( id < 0) return 0;
        trnmnt->nodes[i] = id;
    }


    return trnmnt;

}


int trnmnt_tree_dealloc(trnmnt_tree* tree){

    if(tree == 0 || tree->size == 0 || tree->depth == 0 ) return -1;

    // check if there is a locked mutex in tree
    int size = tree->size;

//    for(int i=0; i<size; i++){
//        int mutex_id = tree->nodes[i];
//        struct kthread_mutex_t *m = &mtable.mutexes[mutex_id];
//        if(m == 0 || !m->allocated || m->locked)
//            return -1;
//    }

    // if the mutexes aren't locked
    for(int i=0; i<size; i++){
        int mutex_id = tree->nodes[i];
        int res = kthread_mutex_dealloc(mutex_id);
        if (res < 0) return -1;

    }

    free(tree->nodes);
    tree->size = 0;
    tree->depth = 0;
    free(tree);
    tree = 0;

    return 0;

}

int trnmnt_tree_acquire_depth(trnmnt_tree* tree,int ID, int depth){
    if(depth == 0) return 0;

    int num_of_leaves = 1 << (depth -1);
    int subtree_size = (1 << depth) -1;  // the size of the tree
    int first_leaf = subtree_size - num_of_leaves;

    int next_id = (int)(ID / 2.0);
    int acquire_index = first_leaf + next_id;

    if(kthread_mutex_lock(tree->nodes[acquire_index]) == -1) return -1;
    return trnmnt_tree_acquire_depth(tree, next_id, depth-1);

}


int trnmnt_tree_acquire(trnmnt_tree* tree,int ID){

    return trnmnt_tree_acquire_depth(tree, ID, tree->depth);
}


int trnmnt_tree_release_depth(trnmnt_tree* tree,int ID, int depth){

    if(depth == 0) return 0;

    int num_of_leaves = 1 << (depth -1);
    int subtree_size = (1 << depth) -1;  // the size of the tree
    int first_leaf = subtree_size - num_of_leaves;

    int next_id = (int)(ID / 2.0);
    int acquire_index = first_leaf + next_id;


    int res = trnmnt_tree_release_depth(tree, next_id, depth-1);

    if(kthread_mutex_unlock(tree->nodes[acquire_index]) == -1) return -1; //TODO: problem id=7 access array

    return res;

}




int trnmnt_tree_release(trnmnt_tree* tree,int ID){
    return trnmnt_tree_release_depth(tree, ID, tree->depth);

}


// TODO: test 24 - deallocted when not supposed to - problem dealloct