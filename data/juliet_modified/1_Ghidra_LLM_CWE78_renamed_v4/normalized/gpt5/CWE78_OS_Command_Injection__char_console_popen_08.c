#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* Constants */
#define COMMAND_BUFFER_SIZE 101

/* Forward declarations */
int main_flow(void);
void vulnerable_command_executor(void);
int always_true(void);
unsigned long print_msg(unsigned long param);

/*
  vulnerable_command_executor:
  Builds a command string in a fixed-size buffer, appends input from stdin,
  and invokes popen/pclose with that command. Buffer size and I/O behavior
  mirror the original implementation.
*/
void vulnerable_command_executor(void)
{
    char *cmd_ptr;
    int condition;
    unsigned int pclose_ret;
    size_t len;
    char *fgets_ret;
    FILE *proc_stream;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Initialize pointer to start at offset 1 of the buffer */
    cmd_ptr = command_buffer + 1;

    /* Zero the writable region (100 bytes) starting at cmd_ptr */
    memset(cmd_ptr, 0, 100);

    /* Prepend "ls " at offsets 1..3 (buffer[1] = 'l', buffer[2] = 's', buffer[3] = ' ') */
    command_buffer[1] = 0x6c; /* 'l' */
    command_buffer[2] = 0x73; /* 's' */
    command_buffer[3] = 0x20; /* ' ' */

    /* Condition check from auxiliary function */
    condition = always_true();
    if ((condition != 0) && (len = strlen(cmd_ptr), 1 < 100 - len)) {
        /* Read from stdin into the command buffer after existing content */
        fgets_ret = fgets(cmd_ptr + len, 100 - (int)len, stdin);
        if (fgets_ret == NULL) {
            /* Report fgets failure (original behavior) */
            print_msg((unsigned long)"fgets() failed");
            cmd_ptr[len] = '\0';
        } else {
            /* Trim trailing newline if present */
            len = strlen(cmd_ptr);
            if ((len != 0) && (cmd_ptr[len - 1] == '\n')) {
                cmd_ptr[len - 1] = '\0';
            }
        }
    }

    /* Invoke popen with the constructed command (kept as in original) */
    proc_stream = popen(cmd_ptr, "w");
    if (proc_stream != NULL) {
        pclose_ret = pclose(proc_stream);
        /* Preserve original assignment semantics */
        proc_stream = (FILE *)(uintptr_t)pclose_ret;
    }

    return;
}

/* main_flow:
   Seeds the PRNG, prints messages, and calls the vulnerable executor.
*/
int main_flow(void)
{
    time_t t;

    t = time((time_t *)0);
    srand((unsigned int)t);
    print_msg((unsigned long)"Calling ...");
    vulnerable_command_executor();
    print_msg((unsigned long)"Finished ");
    return 0;
}

/* always_true:
   Returns a nonzero value to allow the input branch to execute.
*/
int always_true(void)
{
    return 1;
}

/* print_msg:
   Prints a string followed by newline if a non-NULL parameter is provided.
   Mirrors original printf usage.
*/
unsigned long print_msg(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        ret = printf("%s\n", (const char *)param);
        param = (unsigned long)ret;
    }
    return param;
}

/* Provide a minimal main to allow compilation and exercise the flow. */
int main(void)
{
    return main_flow();
}