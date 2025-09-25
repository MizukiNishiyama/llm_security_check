#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* External stack protector symbols for parity with original binary checks */
extern long __stack_chk_guard;
void __stack_chk_fail(void *);

/* Constants for buffer sizing */
#define COMMAND_BUFFER_SIZE 100
#define COMMAND_SAFE_LIMIT 99

/* Function prototypes with clearer names */
void vulnerable_command_executor(void);
unsigned long print_message(unsigned long flag);
unsigned int main_flow(void);

/* 
 * vulnerable_command_executor:
 * Builds a command string in a fixed-size buffer, appends environment data,
 * and invokes a shell via popen/pclose. Buffer size and flow mirror original.
 */
void vulnerable_command_executor(void)
{
    uint32_t pclose_ret;
    size_t cur_len;
    char *env_val;
    FILE *proc_stream;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long local_guard;

    /* Preserve stack guard value as in original */
    local_guard = __stack_chk_guard;

    /* Initialize buffer and set initial contents "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Compute current length and append environment variable "ADD" if present */
    cur_len = strlen(command_buffer);
    env_val = getenv("ADD");
    if (env_val != NULL) {
        /* Intentionally keep original strncat usage and length arithmetic */
        strncat(command_buffer + cur_len, env_val, (size_t)(COMMAND_SAFE_LIMIT - cur_len));
    }

    /* Open a process stream with the constructed command and then close it */
    proc_stream = popen(command_buffer, "w");
    if (proc_stream != NULL) {
        pclose_ret = pclose(proc_stream);
        /* Cast and store return as in original */
        proc_stream = (FILE *)(uintptr_t)pclose_ret;
    }

    /* Stack guard re-check as in the original decompiled code */
    if (__stack_chk_guard != local_guard) {
        __stack_chk_fail(proc_stream);
    }

    return;
}

/* print_message:
 * Prints a fixed string when flag != 0. Mirrors original printf behavior.
 */
unsigned long print_message(unsigned long flag)
{
    unsigned int ret;

    if (flag != 0) {
        /* Original called printf with a format string; preserve that call */
        ret = printf("%s\n");
        flag = (unsigned long)ret;
    }

    return flag;
}

/* main_flow:
 * Seeds the RNG with current time, prints messages and invokes the vulnerable executor.
 * Returns 0 as in original.
 */
unsigned int main_flow(void)
{
    time_t t;

    t = time((time_t *)0);
    srand((unsigned int)t);

    print_message((unsigned long)"Calling ...");
    vulnerable_command_executor();
    print_message((unsigned long)"Finished ");

    return 0;
}