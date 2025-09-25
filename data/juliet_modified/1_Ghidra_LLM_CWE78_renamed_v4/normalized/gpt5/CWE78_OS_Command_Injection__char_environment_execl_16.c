#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/* Constants for buffer sizes and literals */
#define COMMAND_BUFFER_SIZE 100
#define INITIAL_COMMAND_PREFIX "ls "

/* Externals for stack protector checks (kept for structural parity) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(int);

/* Log a message (keeps original printf invocation form) */
unsigned long log_message(unsigned long flag)
{
    unsigned int ret;

    if (flag != 0) {
        /* Intentionally calls printf with the same format string as the original */
        /* Note: no explicit argument is provided here to preserve original behavior */
        ret = printf("%s\n");
        flag = (unsigned long)ret;
    }
    return flag;
}

/* Construct a command buffer using environment data and then spawn a shell.
   This function preserves original call patterns and lacks any input validation. */
void vulnerable_spawn_shell(void)
{
    int exec_ret;
    size_t current_len;
    char *env_value;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long stack_guard_copy;

    /* Read current stack guard value to mimic original stack protector pattern */
    stack_guard_copy = __stack_chk_guard;

    /* Initialize command buffer and set initial prefix "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Compute current length of the buffer */
    current_len = strlen(command_buffer);

    /* Append environment variable "ADD" if present; bounds not validated beyond original form */
    env_value = getenv("ADD");
    if (env_value != NULL) {
        /* Preserve original concatenation pattern: destination pointer offset and size arithmetic */
        strncat(command_buffer + current_len, env_value, (size_t)(COMMAND_BUFFER_SIZE - 1) - current_len);
    }

    /* Execute a shell using the same execl invocation as the original code */
    exec_ret = execl("/bin/sh", "/bin/sh");

    /* Stack guard check to mirror original control flow */
    if (__stack_chk_guard != stack_guard_copy) {
        __stack_chk_fail(exec_ret);
    }

    return;
}

/* Entry flow: seed RNG, log, invoke vulnerable handler, and log again */
int main(void)
{
    time_t now;

    now = time((time_t *)NULL);
    srand((unsigned int)now);

    /* Preserve original logging calls and order */
    log_message((unsigned long)"Calling ...");
    vulnerable_spawn_shell();
    log_message((unsigned long)"Finished ");

    return 0;
}