#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#include "threads/thread.h"
#include "threads/synch.h"
typedef int pid_t;

//Checking file Status
enum load_status
{
  NOT_LOADED, LOAD_SUCCESS, LOAD_FAILED
};
struct process
{
  struct list_elem elem;
  bool is_waited;
  struct semaphore load;
  int exit_status;
  pid_t pid;
  bool is_alive;
  enum load_status load_status;
  struct semaphore wait;
};

//Calling process execute function
tid_t process_execute (const char *);

//Calling process wait function
int process_wait (tid_t);

//Calling process exit function
void process_exit (void);

//Calling process activate function
void process_activate (void);


#endif /* userprog/process.h */

