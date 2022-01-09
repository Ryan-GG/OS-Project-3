#include "userprog/syscall.h"
#include "lib/stdio.h"
#include "lib/string.h"
#include "lib/kernel/stdio.h"
#include <syscall-nr.h>
#include <debug.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <string.h>


static void syscall_handler(struct intr_frame *);
void syscall_close(int fd);
bool syscall_create(const char *file, unsigned initial_size);
pid_t syscall_exec (const char *cmd_line);
void syscall_exit(int status);
int syscall_filesize(int fd);
void syscall_halt(void);
int syscall_open(const char *file);
int syscall_read(int fd, void *buffer, unsigned size);
bool syscall_remove(const char *file);
void syscall_seek(int fd, unsigned position);
int syscall_wait(tid_t tid);
unsigned syscall_tell(int fd);
int syscall_write(int fd, void *buffer, unsigned size);

bool validate_user_pointer(void *user_pointer, int size);
void terminate_invalid_pointer(void);

static bool put_user(uint8_t *udst, uint8_t byte);
static int get_user(const uint8_t *uaddr);
struct file *get_file(int fd);

/* Global Variables */
struct lock filesys_lock;

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&filesys_lock);
}

static void
syscall_handler(struct intr_frame *f)
{
  if(f == NULL)
  {
    syscall_exit(-1);
  }
  if(f->esp == NULL || !validate_user_pointer(f->esp, sizeof(f->esp)))
  {
    syscall_exit(-1);
  }

  int syscall = *(int *)f->esp; //PANIC

  /* Check if argument is fully in user address range */
  if (!is_user_vaddr((void *)(f->esp + 4)))
  {
    syscall_exit(-1);
  }

  switch (syscall)
  {
  case (SYS_CLOSE):
    lock_acquire(&filesys_lock);
    syscall_close(*(int *)(f->esp + 4));
    lock_release(&filesys_lock);
    break;
  case (SYS_CREATE):
    lock_acquire(&filesys_lock);
    bool success = syscall_create((char *)*(int *)(f->esp + 4), *(unsigned int *)(f->esp + 8));
    lock_release(&filesys_lock);
    if ( success ) {
      f->eax = 1;
    } else {
      f->eax = 0;
    }
    break;

  case (SYS_EXEC):
    f->eax = (uint32_t)syscall_exec((char *)*(int *)(f->esp + 4));

    if ((int)(f->eax) == -1)
    {
      syscall_exit(-1);
    }
    break;

  case (SYS_EXIT):
    syscall_exit(*(int *)(f->esp + 4));
    break;

  case (SYS_FILESIZE):
    lock_acquire(&filesys_lock);
    f->eax = (uint32_t)syscall_filesize(*(int *)(f->esp + 4));
    lock_release(&filesys_lock);
    break;

  case (SYS_HALT):
    syscall_halt();
    break;

  case (SYS_OPEN):
    lock_acquire(&filesys_lock);
    f->eax = (uint32_t)syscall_open((char *)*(int *)(f->esp + 4));
    lock_release(&filesys_lock);
    break;

  case (SYS_READ):
    f->eax = (uint32_t)syscall_read(*(int *)(f->esp + 4), (char *)*(int *)(f->esp + 8), *(unsigned *)(f->esp + 12));
    /* Check if read was successful */
    if ((int)(f->eax) == -1)
    {
      syscall_exit(-1);
    }
    break;

  case (SYS_REMOVE):
    lock_acquire(&filesys_lock);
    syscall_remove((char *)*(int *)(f->esp + 4));
    lock_release(&filesys_lock);
    break;

  case (SYS_SEEK):
    lock_acquire(&filesys_lock);
    syscall_seek(*(int *)(f->esp + 4), *(unsigned *)(f->esp + 8));
    lock_release(&filesys_lock);
    break;

  case (SYS_TELL):
    lock_acquire(&filesys_lock);
    f->eax = (uint32_t)syscall_tell(*(int *)(f->esp + 4));
    lock_release(&filesys_lock);
    break;

  case (SYS_WRITE):
    f->eax = (uint32_t)syscall_write(*(int *)(f->esp + 4), (uint8_t *)*(int *)(f->esp + 8), *(unsigned *)(f->esp + 12));
    /* Check if write was successful */
    if ((int)(f->eax) == -1)
    {
      syscall_exit(-1);
    }
    break;
  case (SYS_WAIT):
    f->eax = (uint32_t)syscall_wait(*(int *)(f->esp + 4));
    //if ((int)(f->eax) == -1)
    //{
      //syscall_exit(-1);
    //}
    break;
  default:
    syscall_exit(-1);
    break;
  }
}

void syscall_close(int fd)
{
  if( fd > 1 && fd < 18 ) {
    thread_current()->fds[fd - 2] = 0;
  }
}

bool syscall_create(const char *file, unsigned initial_size)
{
  if( file != NULL && validate_user_pointer( (void *)file, sizeof(file) ) ) {
    return filesys_create(file, initial_size);
  }
  syscall_exit(-1);
}

pid_t syscall_exec(const char *cmd_line) {
  //trying to get file name and check if the file exisits, currently breaks everything

  /*char *cmd_line_new = malloc(strlen(cmd_line));
  strlcpy(cmd_line_new, cmd_line, strlen(cmd_line) + 1);
  char *str = strtok_r(cmd_line_new, " ",NULL);*/
  /*if(!filesys_create(strdup(str), sizeof(cmd_line)))
  {
    syscall_exit(-1);
  }*/

  pid_t result = -1;
  if( cmd_line == NULL || !validate_user_pointer( (void*)cmd_line, sizeof( cmd_line ) ) ) {
    syscall_exit(-1);
  }
  lock_acquire(&filesys_lock);
  result = process_execute( cmd_line );

  /*
  struct file *child_file = filesys_open(cmd_line);
  file_deny_write(child_file);
  */
  
  lock_release( &filesys_lock );
  if(result == -1)
  {
    syscall_exit(-1);
  }
  // don't know what to do yet
  return result;
}

void syscall_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_current()->exit_status = status;

  /* Release any filesys_lock if held by thread */
  if( lock_held_by_current_thread( &filesys_lock ) ) {
    lock_release( &filesys_lock );
  }
  // Check for parent thread, if it exists, access that thread's attribute tracking status of children's exit
  if( thread_current()->parent != NULL ) {
    thread_current()->parent->child_status = status;
  }

  thread_exit();
}

int syscall_filesize(int fd)
{
  struct file *current_file = get_file(fd);

  if (current_file == NULL)
  {
    return -1;
  }
  else
  {
    return file_length(current_file);
  }
}

void syscall_halt()
{
  shutdown_power_off();
}

int syscall_open(const char *file)
{
  if( file == NULL || !validate_user_pointer((void *)file, sizeof(file)) ) {
    syscall_exit(-1);
  }
  struct file *current_file = filesys_open(file);

  if (current_file == NULL)
  {
    return -1;
  }
  else
  {
    for( int i = 0; i < 16; i++ ) {
      if( thread_current()->fds[i] == 0 ) {
        thread_current()->fds[i] = 1;
        thread_current()->files[i] = current_file;
        return i + 2;
      }
    }
    return -1;
  }
}

int syscall_read(int fd, void *buffer, unsigned size)
{
  if(!validate_user_pointer(buffer, size))
  {
    return -1;
  }
  
  if (fd < STDIN_FILENO || fd == STDOUT_FILENO)
  {
    return -1;
  }
  
  // Initialize the input buffer
  input_init();

  // PA02 - STDIN
  if (fd == STDIN_FILENO)
  {
    for (unsigned i = 0; i < size; i++)
    {
      if (!put_user(((uint8_t *)buffer + i), input_getc()))
      {
        return -1;
      }
    }
    return size;
  }

  // PA03 - FILESYS
  lock_acquire( &filesys_lock );
  struct file *file = get_file(fd);
  if (file == NULL)
  {
    return -1;
  }
  int result = file_read(file, buffer, size);
  lock_release( &filesys_lock );
  return result;
}

bool syscall_remove(const char *file)
{
  return filesys_remove(file);
}

void syscall_seek(int fd, unsigned position)
{
  struct file *current_file = get_file(fd);

  if (current_file != NULL)
  {
    file_seek(current_file, position);
  }
}

unsigned syscall_tell(int fd)
{
  struct file *current_file = get_file(fd);

  if (current_file == NULL)
  {
    return -1;
  }
  else
  {
    return file_tell(current_file);
  }
}

int syscall_wait(pid_t pid)
{
  int result = process_wait(pid);
  return result;
}

#define WRITE_LEN 500

int syscall_write(int fd, void *buffer, unsigned size)
{
  if(!validate_user_pointer(buffer, size))
  {
    return -1;
  }
  if (fd < STDOUT_FILENO || fd == STDIN_FILENO)
  {
    return -1;
  }

  // PA02 - STDOUT
  if (fd == STDOUT_FILENO)
  {
    // Store a copy of the length to return on success
    unsigned initial_length = size;
    // Write in chunks of WRITE_LEN bytes defined above
    if (size > WRITE_LEN)
    {
      // Calculate how many bytes remain after dividing into even chunks, and write the excess
      int r = size % WRITE_LEN;
      putbuf((char *)buffer, r);
      size -= r;

      // After writing excess, this assertion should pass
      ASSERT(size % WRITE_LEN == 0);

      // While there's still remaining, write in chunks of WRITE_LEN bytes
      while (size > 0)
      {
        putbuf((char *)buffer, WRITE_LEN);
        size -= WRITE_LEN;
      }
    }

    // Simple case with a single write
    else
    {
      putbuf((char *)buffer, size);
    }
    return initial_length;
  }

  // PA03 - FILESYS
  struct file *file = get_file(fd);
  if (file == NULL)
  {
    return -1;
  }
  lock_acquire( &filesys_lock );
  int result = file_write(file, buffer, size);
  lock_release( &filesys_lock );
  return result;

  // MAKE SURE TO USE FILESYS_LOCK IF WRITING TO FILE
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user(const uint8_t *uaddr)
{
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result)
      : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}

struct file *
get_file(int fd)
{
  if( fd > 1 && fd < 18 ) {
    if( thread_current()->fds[fd - 2] ) {
      return thread_current()->files[fd - 2];
    }
  }

  return NULL;
}

bool validate_user_pointer(void *user_pointer, int size)
{
  // Grab the active page directory, if null then the pointer was unallocated
  void *pd = (void *)active_pd();
  if (pd == NULL)
  {
    return false;
  }

  // There's more wrong than just a bad pointer
  if (size < 0)
  {
    return false;
  }

  if (size == 0)
  {
    if (!is_user_vaddr(user_pointer))
    {
      return false;
    }
    else
    {
      if (pagedir_get_page(pd, user_pointer) == NULL)
      {
        return false;
      }
    }
  }

  // For syscalls with size parameters, check the entire range of addresses
  if (size > 0)
  {
    for (int i = 0; i < size; i++)
    {
      if (!is_user_vaddr(user_pointer + i))
      {
        return false;
      }
      else
      {
        if (pagedir_get_page(pd, user_pointer + i) == NULL)
        {
          return false;
        }
      }
    }
  }

  // Congrats, the pointer is valid
  return true;
}

void terminate_invalid_pointer()
{
}
