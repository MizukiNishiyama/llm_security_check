#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

/* Minimal externs for stack protector handling preserved as in original binary */
extern long __stack_chk_guard;
extern void __stack_chk_fail(long);

/* Global flag mirrored from original binary */
int global_flag = 0;

/* Constants for sizes and defaults */
#define COMMAND_BUFFER_SIZE 100

/* Forward declarations with clearer names */
char *build_command(char *command_buffer);
unsigned long log_message(unsigned long msg);
int vulnerable_main_action(void);
int entry_point(void);

/* 
 * build_command:
 * - Appends input from stdin to the provided command buffer.
 * - The buffer is expected to already contain a prefix (e.g., "ls ").
 * - No additional validation or bounds checks are performed beyond the original logic.
 */
char *build_command(char *command_buffer)
{
    size_t current_len;
    char *fgets_result;

    if ((global_flag != 0) && ((current_len = strlen(command_buffer)), 1 < COMMAND_BUFFER_SIZE - current_len)) {
        /* Read remaining bytes from stdin into the buffer */
        fgets_result = fgets(command_buffer + current_len, (int)(COMMAND_BUFFER_SIZE - current_len), stdin);
        if (fgets_result == NULL) {
            /* Preserve original behavior: call log function and terminate read by null-terminating */
            log_message((unsigned long)"fgets() failed");
            command_buffer[current_len] = '\0';
        } else {
            /* Strip trailing newline if present */
            current_len = strlen(command_buffer);
            if ((current_len != 0) && (command_buffer[current_len - 1] == '\n')) {
                command_buffer[current_len - 1] = '\0';
            }
        }
    }

    return command_buffer;
}

/*
 * log_message:
 * - Wrapper around printf used in original code.
 * - If msg is non-zero, prints a string and returns number of characters printed.
 */
unsigned long log_message(unsigned long msg)
{
    unsigned int ret = 0;

    if (msg != 0) {
        /* Original used printf with a single %s\n format; preserve similar behavior */
        ret = printf("%s\n", (const char *)msg);
    }

    return (unsigned long)ret;
}

/*
 * vulnerable_main_action:
 * - Prepares a command buffer starting with "ls " and then reads user input into it.
 * - Passes the resulting string directly to popen with "w" mode and closes the stream.
 * - Stack protector checks are preserved.
 */
int vulnerable_main_action(void)
{
    unsigned int close_ret;
    char *command_str;
    FILE *pipe_file;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long guard_check;

    /* Preserve stack guard value and check at end */
    guard_check = __stack_chk_guard;

    /* Initialize buffer to zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set initial bytes to 'l', 's', ' ' to form "ls " */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Mirror original global flag set */
    global_flag = 1;

    /* Append user input to the command buffer (no additional validation) */
    command_str = build_command(command_buffer);

    /* Call popen with the constructed command string and "w" mode (preserve original dangerous call) */
    pipe_file = popen(command_str, "w");
    if (pipe_file != NULL) {
        close_ret = pclose(pipe_file);
        pipe_file = (FILE *)(unsigned long)close_ret;
    }

    /* Stack protector check preserved exactly */
    if (__stack_chk_guard != guard_check) {
        __stack_chk_fail((long)pipe_file);
    }

    return 0;
}

/*
 * entry_point:
 * - Seeds the RNG with current time, logs messages, and invokes the vulnerable action.
 */
int entry_point(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);

    log_message((unsigned long)"Calling ...");
    vulnerable_main_action();
    log_message((unsigned long)"Finished ");

    return 0;
}

/* Optional main to allow running; preserves behavior by calling entry_point */
int main(void)
{
    return entry_point();
}