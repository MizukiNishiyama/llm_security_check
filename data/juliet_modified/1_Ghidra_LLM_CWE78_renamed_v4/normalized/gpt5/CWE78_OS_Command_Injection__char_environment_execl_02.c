#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/*
 * Readability-improved version of the decompiled logic.
 * Vulnerabilities and dangerous function calls are kept intact.
 */

/* Constants */
#define CMD_BUFFER_SIZE 100
#define INITIAL_COMMAND "ls "

/* External symbols used in original binary stack protect checks */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Forward declarations */
void vulnerable_execute_from_env(void);
int main_routine(void);
unsigned long print_if_nonzero(unsigned long value);

/* Build a command buffer, append contents of ADD environment variable (if any),
   then execute /bin/sh. Buffer boundaries and lack of validation are preserved. */
void vulnerable_execute_from_env(void)
{
    int ret_code;
    size_t current_len;
    char *env_add;
    char command_buffer[CMD_BUFFER_SIZE];
    long saved_stack_guard;

    /* replicate stack protector usage from original */
    saved_stack_guard = __stack_chk_guard;

    /* initialize buffer */
    memset(command_buffer, 0, CMD_BUFFER_SIZE);
    /* set initial bytes to "ls " */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    current_len = strlen(command_buffer);

    /* read ADD environment variable and append without proper validation */
    env_add = getenv("ADD");
    if (env_add != NULL) {
        /* keep the original call pattern: append at buffer+current_len with limited count */
        strncat(command_buffer + current_len, env_add, (size_t)(CMD_BUFFER_SIZE - 1 - current_len));
    }

    /* execute a shell (original used execl("/bin/sh","/bin/sh")) */
    ret_code = execl("/bin/sh", "/bin/sh");

    /* replicate stack protector check */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail(ret_code);
    }

    return;
}

/* Initialize PRNG based on current time, print a message, run the vulnerable function,
   then print another message. */
int main_routine(void)
{
    time_t now;

    now = time((time_t *)NULL);
    srand((unsigned int)now);

    print_if_nonzero((unsigned long)"Calling ...");
    vulnerable_execute_from_env();
    print_if_nonzero((unsigned long)"Finished ");

    return 0;
}

/* Print a string if the parameter is non-zero. Mirrors original behavior. */
unsigned long print_if_nonzero(unsigned long value)
{
    unsigned int printed;

    if (value != 0) {
        printed = printf("%s\n");
        value = (unsigned long)printed;
    }
    return value;
}