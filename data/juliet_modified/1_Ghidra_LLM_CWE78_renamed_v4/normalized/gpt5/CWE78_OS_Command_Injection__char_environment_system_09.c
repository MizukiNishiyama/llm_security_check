#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* Stack protector symbols (preserved pattern) */
extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* Constants */
#define COMMAND_BUFFER_SIZE 100
#define ENV_ADD_NAME "ADD"
#define TRUE_FLAG 1

/* Forward declarations */
void vulnerable_command_executor(void);
int entry_point(void);
void print_message(const char *message);

/* Vulnerable function: builds a command in a fixed-size buffer using getenv and calls system.
   Note: preserves original behavior and lack of bounds/validation checks. */
void vulnerable_command_executor(void)
{
    int system_ret;
    size_t current_len;
    char *env_value;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long local_canary;

    /* Preserve stack guard check pattern */
    local_canary = __stack_chk_guard;

    /* Initialize buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */

    /* Conditional block matching original control flow */
    if (TRUE_FLAG != 0) {
        current_len = strlen(command_buffer);
        env_value = getenv(ENV_ADD_NAME);
        if (env_value != NULL) {
            /*
             * Concatenate environment value into the fixed buffer.
             * The original code used a checked strncat variant; here we call strncat
             * with a size computed in the same manner (no additional validation).
             */
            strncat(command_buffer + current_len, env_value, COMMAND_BUFFER_SIZE - current_len);
        }
    }

    /* Execute constructed command (kept as original system call) */
    system_ret = system(command_buffer);
    if (system_ret == 0) {
        if (__stack_chk_guard == local_canary) {
            return;
        }
        __stack_chk_fail();
    }

    print_message("command execution failed!");
    _exit(1);
}

/* Entry point-like function: seeds RNG, logs, invokes vulnerable executor. */
int entry_point(void)
{
    time_t t;
    t = time(NULL);
    srand((unsigned int)t);

    print_message("Calling ...");
    vulnerable_command_executor();
    print_message("Finished ");

    return 0;
}

/* Simple print helper retained for clarity. */
void print_message(const char *message)
{
    if (message != NULL) {
        printf("%s\n", message);
    }
}