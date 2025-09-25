#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* Constants for readability */
#define BUFFER_SIZE 100
#define INITIAL_CMD_PREFIX "ls "
#define INPUT_FILE_PATH "/tmp/file.txt"
#define INPUT_FILE_MODE "r"
#define POPEN_MODE "w"

/* External stack check symbols (preserved behavior) */
extern long __stack_chk_guard;
void __stack_chk_fail(void *);

/* Forward declarations (preserve original signatures/behavior) */
ulong log_message(ulong param);
void vulnerable_command_runner(void);
int run_sequence(void);

/* Log-like function: prints if non-zero parameter (keeps original unsafe printf usage) */
ulong log_message(ulong param)
{
    unsigned int result;

    if (param != 0) {
        /* Intentionally calling printf with a format that expects an argument but none is provided,
           preserved from original decompiled logic. */
        result = printf("%s\n");
        param = (ulong)result;
    }
    return param;
}

/* Main vulnerable routine: builds a command, optionally appends file content, then popen()s it */
void vulnerable_command_runner(void)
{
    unsigned int close_result;
    size_t prefix_len;
    FILE *file;
    char *fgets_ret;
    char command_buffer[BUFFER_SIZE];
    long saved_stack_guard;

    /* Preserve stack guard check behavior */
    saved_stack_guard = __stack_chk_guard;

    /* Initialize command buffer and set an initial command prefix */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    prefix_len = strlen(command_buffer);

    /* Attempt to read additional input from a file into the command buffer */
    if ((1 < (int)(BUFFER_SIZE - prefix_len)) &&
        (file = fopen(INPUT_FILE_PATH, INPUT_FILE_MODE), file != (FILE *)0x0)) {

        fgets_ret = fgets(command_buffer + prefix_len, BUFFER_SIZE - (int)prefix_len, file);
        if (fgets_ret == (char *)0x0) {
            /* Preserve original behavior of calling logging function on fgets failure */
            log_message((ulong)"fgets() failed");
            command_buffer[prefix_len] = '\0';
        }
        fclose(file);
    }

    /* Execute the constructed command via popen */
    file = popen(command_buffer, POPEN_MODE);
    if (file != (FILE *)0x0) {
        close_result = pclose(file);
        file = (FILE *)(unsigned long)close_result;
    }

    /* Final stack guard verification (preserved behavior) */
    if (__stack_chk_guard == saved_stack_guard) {
        return;
    }

    __stack_chk_fail(file);
}

/* Sequence starter: seeds RNG, logs, runs vulnerable routine, logs again */
int run_sequence(void)
{
    time_t t;

    t = time((time_t *)0x0);
    srand((unsigned int)t);
    log_message((ulong)"Calling ...");
    vulnerable_command_runner();
    log_message((ulong)"Finished ");
    return 0;
}

/* Entry point */
int main(void)
{
    return run_sequence();
}