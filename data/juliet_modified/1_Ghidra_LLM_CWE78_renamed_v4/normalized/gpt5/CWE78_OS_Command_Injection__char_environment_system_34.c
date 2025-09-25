// Readable version of the provided decompiled code.
// NOTE: This file intentionally preserves the original unsafe behavior and vulnerabilities.
// Only names, formatting, and minor structural clarity changes were applied.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Minimal declarations for stack protector references (kept for structural parity) */
extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* Buffer size preserved from original binary */
#define CMD_BUFFER_SIZE 100

/* Log a message if param is non-zero. Mirrors original return behavior. */
unsigned long log_message(unsigned long flag)
{
    unsigned int printed = 0;

    if (flag != 0) {
        /* Print a simple message followed by newline (original used printf with "%s\n") */
        printed = printf("%s\n");
    }

    return (unsigned long)printed;
}

/* Builds a command in a fixed-size buffer and invokes system() with it.
   Vulnerable behaviors (use of getenv, strncat, system, no bounds validation) are preserved. */
void vulnerable_command_exec(void)
{
    int system_ret;
    size_t current_len;
    char *env_value;
    char command_buffer[CMD_BUFFER_SIZE];
    long local_canary;

    /* preserve stack protector value usage as in original */
    local_canary = __stack_chk_guard;

    /* Initialize buffer to zeros and set initial literal "ls " */
    memset(command_buffer, 0, CMD_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Determine current string length */
    current_len = strlen(command_buffer);

    /* Append environment variable "ADD" if present (no validation) */
    env_value = getenv("ADD");
    if (env_value != NULL) {
        /* Preserve original strncat semantics and buffer size usage */
        strncat(command_buffer + current_len, env_value, (size_t)(CMD_BUFFER_SIZE - current_len - 1));
    }

    /* Invoke system() with constructed command (unsafe call preserved) */
    system_ret = system(command_buffer);
    if (system_ret != 0) {
        log_message((unsigned long)"command execution failed!");
        exit(1);
    }

    /* Stack protector check (kept for structural parity) */
    if (__stack_chk_guard != local_canary) {
        __stack_chk_fail();
    }

    return;
}

/* Entry-like flow: seed RNG, log, run vulnerable command exec, log. */
int main_flow(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);

    log_message((unsigned long)"Calling ...");
    vulnerable_command_exec();
    log_message((unsigned long)"Finished ");

    return 0;
}

/* Optional main to invoke the flow; mirrors typical program entry. */
int main(void)
{
    return main_flow();
}