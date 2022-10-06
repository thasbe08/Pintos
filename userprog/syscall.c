#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"


#define ARG_CODE 0
#define ARG_0    4
#define ARG_1    8
#define ARG_2    12
#define EXIT_ERROR -1
#define MAX_BUF 512
#define MIN_FD 2

//file structure and file descriptors
struct filemap
{
  struct list_elem elem;
  int fd;               
  struct file *file;    
};

//Variable declaration
static struct semaphore file_sema;
static uint32_t load_stack (struct intr_frame *f, int);
static void syscall_handler (struct intr_frame *f);
bool is_valid_ptr (void *);
bool is_valid_buffer (void *buffer, size_t length);
bool is_valid_string (const char *str);
bool sys_create (const char *name, unsigned int initial_size);
bool sys_remove (const char *file);
int sys_wait (pid_t pid);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned length);
int sys_write (int fd, const void *buffer, unsigned int length);
void sys_close (int fd);
void sys_seek (int fd, unsigned position);
void sys_halt (void);
void sys_exit (int status);
pid_t sys_exec (const char *cmd_line);
unsigned sys_tell (int fd);

struct filemap *get_file (int fd);

//Function to check if uaddr is below PHYS_BASE.
static int 
get_user (const uint8_t *uaddr)
{
  if ((uint32_t) uaddr >= (uint32_t) PHYS_BASE)
    return -1;
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

//Function to check if udst is below PHYS_BASE.
static bool 
put_user (uint8_t *udst, uint8_t byte)
{
  if ((uint32_t) udst < (uint32_t) PHYS_BASE)
    return false;

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


void 
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  sema_init (&file_sema, 1);
}

static 
void syscall_handler (struct intr_frame *f)
{
  int code = (int) load_stack (f, ARG_CODE);

  switch (code)
    {
      case SYS_HALT:
        sys_halt();
        break;
      case SYS_EXIT:
        sys_exit ((int) load_stack (f, ARG_0));
        break;
      case SYS_EXEC:
        f->eax = sys_exec ((const char *) load_stack (f, ARG_0));
        break;
      case SYS_WAIT:
        f->eax = sys_wait ((pid_t) load_stack (f, ARG_0));
        break;
      case SYS_CREATE:
        f->eax = sys_create ((const char *) load_stack (f, ARG_0),
          (unsigned int) load_stack (f, ARG_1));
        break;
      case SYS_REMOVE:
        f->eax = sys_remove ((const char *) load_stack (f, ARG_0));
        break;
      case SYS_OPEN:
        f->eax = sys_open ((const char *) load_stack (f, ARG_0));
        break;
      case SYS_FILESIZE:
        f->eax = sys_filesize ((int) load_stack (f, ARG_0));
        break;
      case SYS_READ:
        f->eax = sys_read ((int) load_stack (f, ARG_0),
            (void *) load_stack (f, ARG_1),
            (unsigned int) load_stack (f, ARG_2));
        break;
      case SYS_WRITE:
        f->eax = sys_write ((int) load_stack (f, ARG_0),
            (const void *) load_stack (f, ARG_1),
            (unsigned int) load_stack (f, ARG_2));
        break;
      case SYS_SEEK:
        sys_seek ((int) load_stack (f, ARG_0),
          (unsigned) load_stack (f, ARG_1));
        break;
      case SYS_TELL:
        f->eax = sys_tell ((int) load_stack (f, ARG_0));
        break;
      case SYS_CLOSE:
        sys_close ((int) load_stack (f, ARG_0));
        break;
      default:
        sys_exit (EXIT_ERROR);
        break;
    }
}

//Function to validate user pointer
bool 
is_valid_ptr (void *vaddr)
{
  if (get_user ((uint8_t *) vaddr) == -1)
    return false;
  return true;
}

//Function to validate string lenght
bool 
is_valid_buffer (void *buffer, size_t length)
{
  size_t i;
  char *buf = (char *) buffer;
  for (i = 0; i < length; i++)
    {
      if (!is_valid_ptr (buf + i))
        return false;
    }
  return true;
}

//Function to validate stack pointer
static 
uint32_t load_stack (struct intr_frame *f, int offset)
{
  if (!is_valid_ptr (f->esp + offset))
    sys_exit (EXIT_ERROR);
  return *((uint32_t *) (f->esp + offset));
}

//Function to terminate
void 
sys_halt (void)
{
  shutdown_power_off ();
}

//Function to validate unknown string length
bool 
is_valid_string (const char *str)
{
  int c;
  size_t i = 0;
  while (1)
    {
      c = get_user ((uint8_t *) (str + i));
      if (c == -1)
        return false;
      if (c == '\0')
        return true;
      i++;
    }
}

//Function to wait for pid varification
int 
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

//Function to create file with size
bool 
sys_create (const char *name, unsigned int initial_size)
{
  if (!is_valid_string(name))
    sys_exit (EXIT_ERROR);
  bool success;
  sema_down (&file_sema);
  success = filesys_create (name, initial_size);
  sema_up (&file_sema);

  return success;
}

//Function to terminate user process
void 
sys_exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  thread_exit ();
}

//Function to cli arg/ return process id
pid_t
sys_exec (const char *cmd_line)
{
  if (!is_valid_string (cmd_line))
    sys_exit (EXIT_ERROR);
  return process_execute (cmd_line);
}

//Function to open file
int 
sys_open (const char *file)
{
  if (!is_valid_string (file))
    sys_exit (EXIT_ERROR);
  int fd = MIN_FD;
  struct filemap *fm;
  struct thread *cur = thread_current ();

  while (fd >= MIN_FD && get_file (fd) != NULL)
    fd++;

  if (fd < MIN_FD)
    sys_exit (EXIT_ERROR);
  fm = malloc (sizeof (struct filemap));
  if (fm == NULL)
    return -1;

  fm->fd = fd;
  sema_down (&file_sema);
  fm->file = filesys_open (file);
  sema_up (&file_sema);

  if (fm->file == NULL)
    {
      free (fm);
      return -1;
    }
  list_push_back (&cur->files, &fm->elem);
  return fm->fd;
}

//Function to remove file
bool 
sys_remove (const char *file)
{
  if (!is_valid_string (file))
    sys_exit (EXIT_ERROR);
  bool success;
  sema_down (&file_sema);
  success = filesys_remove (file);
  sema_up (&file_sema);

  return success;
}



//Function to get file size
int 
sys_filesize (int fd)
{
  struct filemap *fm = get_file (fd);
  int size;
  if (fm == NULL)
    return -1;
  sema_down (&file_sema);
  size = file_length (fm->file);
  sema_up (&file_sema);

  return size;
}

//Function to buffer to file write
int 
sys_write (int fd, const void *buffer, unsigned int length)
{
  struct filemap *fm;
  unsigned int len;
  char *buf;
  int ret;
  if (!is_valid_buffer ((void *) buffer, length))
    sys_exit (EXIT_ERROR);

  if (fd == STDOUT_FILENO)
    {
      len = length;
      buf = (char *) buffer;
      while (len > MAX_BUF) {
        putbuf ((const char *) buf, MAX_BUF);
        len -= MAX_BUF;
        buf += MAX_BUF;
      }
      putbuf ((const char *) buf, len);
      return length;
    }

  fm = get_file (fd);
  if (fm == NULL)
    sys_exit (EXIT_ERROR);
  sema_down (&file_sema);
  ret = file_write (fm->file, buffer, length);
  sema_up (&file_sema);
  return ret;
}

//Function to read the file to buffer
int 
sys_read (int fd, void *buffer, unsigned length)
{
  size_t i = 0;
  struct filemap *fm;
  int ret;

  if (fd == STDIN_FILENO)
    {
      while (i++ < length)
        if (!put_user (((uint8_t *) buffer + i), (uint8_t) input_getc ()))
          sys_exit (EXIT_ERROR);

      return i;
    }
  if (!is_valid_buffer (buffer, length))
    sys_exit (EXIT_ERROR);
  fm = get_file (fd);
  if (fm == NULL)
    sys_exit (EXIT_ERROR);
  sema_down (&file_sema);
  ret = file_read (fm->file, buffer, length);
  sema_up (&file_sema);

  return ret;
}

//Function to move to position of file
void 
sys_seek (int fd, unsigned position)
{
  struct filemap *fm = get_file (fd);
  if (fm == NULL)
    return;
  sema_down (&file_sema);
  file_seek (fm->file, position);
  sema_up (&file_sema);
}

//Function to get the current position
unsigned 
sys_tell (int fd)
{
  struct filemap *fm = get_file (fd);
  unsigned int ret;
  if (fm == NULL)
    return 0;
  sema_down (&file_sema);
  ret = file_tell (fm->file);
  sema_up (&file_sema);

  return ret;
}

//Function to close the file
void 
sys_close (int fd)
{
  struct filemap *fm = get_file (fd);
  if (fm == NULL)
    return;
  sema_down (&file_sema);
  file_close (fm->file);
  sema_up (&file_sema);
  list_remove (&fm->elem);
  free (fm);
}

//Function to close all files with process exit
void 
close_all_files (struct thread *t)
{
  struct list_elem *e;
  struct filemap *fm;
  e = list_begin (&t->files);

  while (e != list_end (&t->files))
    {
      fm = list_entry (e, struct filemap, elem);
      e = list_next (e);
      sema_down (&file_sema);
      file_close (fm->file);
      sema_up (&file_sema);
      list_remove (&fm->elem);
      free (fm);
    }
}

//Function to validate filemap
struct 
filemap * get_file(int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct filemap *fm;
  for (e = list_begin (&cur->files); e != list_end (&cur->files);
    e = list_next (e))
    {
      fm = list_entry (e, struct filemap, elem);

      if (fm->fd == fd)
        return fm;
    }
  return NULL;
}


