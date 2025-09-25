#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* Minimal external stack protector symbols (kept as in original) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(int);

/* Constants for magic numbers refactoring */
#define COMMAND_BUFFER_SIZE 100

/* Renamed functions and variables for readability while preserving behavior */

/* Builds a command in a local buffer using environment variable "ADD"
   and then invokes /bin/sh via execl. Buffer sizes and call patterns
   are intentionally unchanged. */
void vulnerable_shell_invoker(void)
{
    int loop_index;
    size_t current_len;
    char *env_ptr;
    int exec_ret;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long saved_stack_guard;

    /* Save stack guard as in original layout */
    saved_stack_guard = __stack_chk_guard;

    /* Initialize buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Seed command prefix: "ls " (characters set explicitly) */
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;    /* 's' */
    command_buffer[2] = 0x20;    /* ' ' */

    /* Single-iteration loop preserved exactly */
    for (loop_index = 0; loop_index < 1; loop_index = loop_index + 1) {
        /* Compute current length and append environment value if present */
        current_len = strlen(command_buffer);
        env_ptr = getenv("ADD");
        if (env_ptr != NULL) {
            /* Use strncat with the same remaining-size calculation as original.
               This preserves potential overflow behavior when env content is large. */
            strncat(command_buffer + current_len, env_ptr, (size_t)(COMMAND_BUFFER_SIZE - current_len));
        }
    }

    /* Invoke shell. Call pattern preserved (no terminating NULL argument provided). */
    exec_ret = execl("/bin/sh", "/bin/sh");

    /* Stack guard check identical to original */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail(exec_ret);
    }

    return;
}

/* Wrapper that seeds rand and calls the vulnerable invoker */
int main_invoker(void)
{
    time_t now;

    now = time((time_t *)0);
    srand((unsigned int)now);

    message_printer("Calling ...");
    vulnerable_shell_invoker();
    message_printer("Finished ");

    return 0;
}

/* Prints a message. Original semantics (format string with missing argument)
   are preserved: when a non-zero parameter is provided, printf is called
   with "%s\n" but no matching argument. */
unsigned long message_printer(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        ret = printf("%s\n");
        param = (unsigned long)ret;
    }

    return param;
}

/* If this file is compiled as a standalone program, call main_invoker */
int main(void)
{
    return main_invoker();
}