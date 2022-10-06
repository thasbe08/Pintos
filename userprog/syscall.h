#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

void syscall_init (void);

//calling close all files function
void close_all_files (struct thread *t);

#endif /* userprog/syscall.h */

