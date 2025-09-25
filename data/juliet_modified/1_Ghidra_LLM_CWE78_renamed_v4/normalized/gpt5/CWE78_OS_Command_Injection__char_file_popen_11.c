#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

/* Constants for magic values */
#define CMD_BUFFER_SIZE 100
#define INITIAL_CMD_PREFIX "ls "

/* External stack protector symbols (preserve original check behavior) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void *);

/* Forward declarations */
int vulnerable_file_command_executor(void);
int main_behavior(void);
unsigned long vulnerable_print(unsigned long param);
int always_true(void);

/* 
 * vulnerable_file_command_executor:
 * - Builds a command buffer starting with "ls "
 * - Attempts to append contents read from /tmp/file.txt using fgets
 * - Executes the resulting command using popen/pclose
 *
 * Note: Buffer sizes, lack of input validation, and use of popen are preserved.
 */
int vulnerable_file_command_executor(void)
{
    int ret;
    unsigned int close_status;
    size_t current_len;
    FILE *file;
    char *fgets_result;
    char command_buffer[CMD_BUFFER_SIZE];
    long local_guard;

    /* preserve stack protector value for later comparison */
    local_guard = __stack_chk_guard;

    /* initialize command buffer to zeros and set initial "ls " prefix */
    memset(command_buffer, 0, CMD_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* call helper that returns non-zero in original */
    ret = always_true();

    /* If helper indicates to proceed, try to read additional data from file and append */
    if ((ret != 0) &&
        (current_len = strlen(command_buffer), 1 < (size_t)(CMD_BUFFER_SIZE - current_len)) &&
        (file = fopen("/tmp/file.txt", "r"), file != NULL)) {

        fgets_result = fgets(command_buffer + current_len,
                             (int)(CMD_BUFFER_SIZE - current_len),
                             file);
        if (fgets_result == NULL) {
            /* preserve original behavior: call vulnerable_print with string literal */
            vulnerable_print((unsigned long)"fgets() failed");
            /* restore string terminator at original length */
            command_buffer[current_len] = '\0';
        }
        fclose(file);
    }

    /* Execute the constructed command using popen/pclose (behavior preserved) */
    file = popen(command_buffer, "w");
    if (file != NULL) {
        close_status = pclose(file);
        file = (FILE *)(unsigned long)close_status;
    }

    /* preserve original stack protector check and failure call */
    if (__stack_chk_guard == local_guard) {
        return 0;
    }

    __stack_chk_fail(file);
    return 0; /* unreachable, but keeps signature consistent */
}

/* 
 * main_behavior:
 * - Seeds PRNG with current time
 * - Calls vulnerable_file_command_executor with informational prints
 */
int main_behavior(void)
{
    time_t current_time;

    current_time = time(NULL);
    srand((unsigned int)current_time);

    vulnerable_print((unsigned long)"Calling ...");
    vulnerable_file_command_executor();
    vulnerable_print((unsigned long)"Finished ");
    return 0;
}

/* 
 * vulnerable_print:
 * - Preserves original flawed printf usage: prints "%s\n" with no argument when param != 0
 * - Returns param or result as in original
 */
unsigned long vulnerable_print(unsigned long param)
{
    unsigned int result;

    if (param != 0) {
        /* Intentionally call printf with a format expecting an argument but none provided,
           preserving original undefined behavior. */
        result = printf("%s\n");
        param = (unsigned long)result;
    }
    return param;
}

/* Simple helper that returns 1 in the original code */
int always_true(void)
{
    return 1;
}

/* Provide a main to allow compilation/execution if linked; not required by spec */
int main(void)
{
    return main_behavior();
}