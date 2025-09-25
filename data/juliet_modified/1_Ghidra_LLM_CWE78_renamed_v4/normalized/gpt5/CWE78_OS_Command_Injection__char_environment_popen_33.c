#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Constants */
#define COMMAND_BUFFER_SIZE 100

/* External stack check symbols (kept for parity with original flow) */
extern void __stack_chk_fail(void *);
extern void * __stack_chk_guard;

/* Vulnerable function: builds a command string from a fixed prefix and an environment variable,
   then executes it with popen. No input validation or bounds protections are performed. */
void vulnerable_execute_from_env(void)
{
    unsigned int return_code;
    size_t prefix_len;
    char *env_value;
    FILE *pipe;
    char command_buffer[COMMAND_BUFFER_SIZE];
    void *saved_stack_guard;

    /* Save current stack guard value (mirrors original stack-check pattern) */
    saved_stack_guard = __stack_chk_guard;

    /* Initialize command buffer to zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set fixed prefix "ls " into the buffer (as bytes) */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    /* Calculate current length of the buffer */
    prefix_len = strlen(command_buffer);

    /* Append environment variable "ADD" to the command buffer without validation */
    env_value = getenv("ADD");
    if (env_value != NULL) {
        /* Intentionally using strncat with remaining buffer size (no additional checks) */
        strncat(command_buffer + prefix_len, env_value, (COMMAND_BUFFER_SIZE - 1) - prefix_len);
    }

    /* Execute the constructed command using popen (mode "w" as in original) */
    pipe = popen(command_buffer, "w");
    if (pipe != NULL) {
        return_code = pclose(pipe);
        pipe = (FILE *)(uintptr_t)return_code;
    }

    /* Stack guard verification (mirrors original flow) */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail(pipe);
    }

    return;
}