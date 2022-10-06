#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif

#define THREAD_MAGIC 0xcd6abf4b			//	Random value, detect stackoverflow
static struct list ready_list;			//	list of ready threads.
static struct list all_list;			//	list of all processes.
static struct thread *idle_thread;		//	Idle thread
static struct thread *initial_thread;	//	Initial thread
static struct lock tid_lock;			//	allocate_tid() lock

//	kernel_thread() stack frame
struct kernel_thread_frame
{
  void *eip;            
  thread_func *function;
  void *aux;            
};

// used for tick counters
static long long idle_ticks;  
static long long kernel_ticks;
static long long user_ticks;  

// scheduling
#define TIME_SLICE 4
static unsigned thread_ticks;

bool thread_mlfqs;	//	by default using round-robin or uses multi-level feedback queue scheduler

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);

#ifdef USERPROG
static void init_thread (struct thread *, const char *name, int priority,
  bool is_user);
#else
static void init_thread (struct thread *, const char *name, int priority);
#endif

static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializing the threading mechanism. 
   Initializing the run queue and tid lock.*/
void thread_init (void)
{
  ASSERT (intr_get_level () == INTR_OFF);
  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  initial_thread = running_thread ();

#ifdef USERPROG
  init_thread (initial_thread, "main", PRI_DEFAULT, false);
#else
  init_thread (initial_thread, "main", PRI_DEFAULT);
#endif
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

//	Enables intrupts and starts preemptive thread scheduling.
void thread_start (void)
{
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
#if USERPROG
  thread_create ("idle", PRI_MIN, idle, &idle_started, false);
#else
  thread_create ("idle", PRI_MIN, idle, &idle_started);
#endif
  intr_enable ();
  sema_down (&idle_started);
}

// Timer tick called by timer interupt handler
void thread_tick (void)
{
  struct thread *t = thread_current ();
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

// 	Prints idle, kernel and user ticks
void thread_print_stats (void)
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creating a new kernel thread with provided priority.
   Adds to the ready queue and returns thread indentification */
#if USERPROG
tid_t
thread_create (const char *name, int priority, thread_func *function,
  void *aux, bool is_user)
#else
tid_t
thread_create (const char *name, int priority, thread_func *function,
  void *aux)
#endif
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;
#ifdef USERPROG
  init_thread (t, name, priority, is_user);
#else
  init_thread (t, name, priority);
#endif
  tid = t->tid = allocate_tid ();
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

#ifdef USERPROG
  t->parent = thread_current ();
#endif
  thread_unblock (t);
  return tid;
}

//	Blocking a thread until thread_unblock() is called
void thread_block (void)
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

//	Unblocks a thread and makes it ready to be run.
void thread_unblock (struct thread *t)
{
  enum intr_level old_level;
  ASSERT (is_thread (t));
  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_push_back (&ready_list, &t->elem);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

// Returns the thread name
const char * thread_name (void)
{
  return thread_current ()->name;
}

//	Returns running thread with validations
struct thread * thread_current (void)
{
  struct thread *t = running_thread ();
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);
  return t;
}

// Returns thread tid
tid_t thread_tid (void)
{
  return thread_current ()->tid;
}

// Removes the thread from the schedule and destroys it
void thread_exit (void)
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

// Yields the CPU
void thread_yield (void)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread)
    list_push_back (&ready_list, &cur->elem);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

//	Callind the func on every thread and passing aux
void thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;
  ASSERT (intr_get_level () == INTR_OFF);
  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

// Sets new priority to the thead
void thread_set_priority (int new_priority)
{
  thread_current ()->priority = new_priority;
}

// Returning the current thread priority
int thread_get_priority (void)
{
  return thread_current ()->priority;
}

// Set threads nice value
void thread_set_nice (int nice UNUSED)
{
  
}

// Return threads nice value
int thread_get_nice (void)
{
  return 0;
}

// Returns system load average
int thread_get_load_avg (void)
{
  return 0;
}

// Returns threads cpu value
int thread_get_recent_cpu (void)
{
  return 0;
}

/* Idle thread is run when there is no other threads in ready state.\
   Scheduled once at the begining and initializes idle_thread.
   When up semaphore is passed, its blocked instantly
   Only when the ready list is empty, it is moved to next_thread_to_run() */
static void
idle (void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;)
    {
      intr_disable ();
      thread_block ();
      asm volatile ("sti; hlt" : : : "memory");
    }
}

// Basis for a kernel thread
static void kernel_thread (thread_func *function, void *aux)
{
  ASSERT (function != NULL);
  intr_enable ();
  function (aux);
  thread_exit ();
}

// Returns the running thread
struct thread * running_thread (void)
{
  uint32_t *esp;
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

// Returns true if its a valid thread
static bool is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

// Initialization of T as a blocked thread named NAME.

#ifdef USERPROG
static void
init_thread (struct thread *t, const char *name, int priority, bool is_user)
#else
static void
init_thread (struct thread *t, const char *name, int priority)
#endif
{
  enum intr_level old_level;
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);
  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;

#ifdef USERPROG
  t->is_user = is_user;
  t->exit_status = -1;
  list_init (&t->children);
  t->parent = NULL;
  list_init (&t->files);
  t->exec = NULL;
#endif

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

// Assigs a byte frame on thread T stack head and returns pointer
static void * alloc_frame (struct thread *t, size_t size)
{
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);
  t->stack -= size;
  return t->stack;
}

/* Selects and returns the next thread to be scheduled.
   If running queue is empty, returns an idle thread.*/
static struct thread * next_thread_to_run (void)
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

// Activated the new threads page table and completes the thread switch
void thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  ASSERT (intr_get_level () == INTR_OFF);
  cur->status = THREAD_RUNNING;
  thread_ticks = 0;

#ifdef USERPROG
  process_activate ();
#endif
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread)
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* A new process scheduling.
   Finding another thread to run and switches to it*/
static void schedule (void)
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));
  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

// Returns tid for new thread
static tid_t allocate_tid (void)
{
  static tid_t next_tid = 1;
  tid_t tid;
  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}


uint32_t thread_stack_ofs = offsetof (struct thread, stack);	//offset for stack within struct thread
#ifdef USERPROG

// Removes a pointer from parent thread
void remove_parent (tid_t tid)
{
  struct list_elem *e;
  struct thread *t;
  for (e = list_begin (&all_list); e != list_end (&all_list);
    e = list_next (e))
    {
      t = list_entry (e, struct thread, allelem);
      if (is_thread (t) && t->tid == tid && t->parent != NULL)
        {
          t->parent = NULL;
          return;
        }
    }
}
#endif
