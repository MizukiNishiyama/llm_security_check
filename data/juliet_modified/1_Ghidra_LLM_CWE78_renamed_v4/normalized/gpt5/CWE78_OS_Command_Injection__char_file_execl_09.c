#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Minimal stack protector symbols for consistency with original Decompiled code */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Constants for clarity */
#define COMMAND_BUFFER_SIZE 100
#define INPUT_FILE_PATH "/tmp/file.txt"
#define SHELL_PATH "/bin/sh"

/* Forward declarations */
void vulnerable_network_handler(void);
int main_flow(void);
unsigned long print_status(unsigned long value);

/*
 * vulnerable_network_handler
 * - Prepares a command buffer, optionally appends contents from a file,
 *   and then executes a shell. Buffer sizes and unsafe calls are preserved.
 */
void vulnerable_network_handler(void)
{
    int execl_ret;
    size_t current_len;
    FILE *fp;
    char *fgets_ret;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long local_guard;

    /* Capture stack guard value as in original binary */
    local_guard = __stack_chk_guard;

    /* Initialize buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set initial contents to "ls " */
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    /* Attempt to append data from a file into the buffer */
    if (((1 != 0) && (current_len = strlen(command_buffer), 1 < COMMAND_BUFFER_SIZE - current_len)) &&
        (fp = fopen(INPUT_FILE_PATH, "r"), fp != NULL)) {

        fgets_ret = fgets(command_buffer + current_len, COMMAND_BUFFER_SIZE - (int)current_len, fp);
        if (fgets_ret == NULL) {
            /* Preserve original behavior: call helper and terminate string at previous length */
            print_status((unsigned long)"fgets() failed");
            command_buffer[current_len] = '\0';
        }
        fclose(fp);
    }

    /* Dangerous call preserved exactly as in original */
    execl_ret = execl(SHELL_PATH, SHELL_PATH);

    /* Stack guard check as in original */
    if (__stack_chk_guard == local_guard) {
        return;
    }

    __stack_chk_fail(execl_ret);
}

/*
 * main_flow
 * - Seeds RNG, logs, invokes the vulnerable handler, logs again.
 */
int main_flow(void)
{
    time_t t;

    t = time((time_t *)0);
    srand((unsigned int)t);
    print_status((unsigned long)"Calling ...");
    vulnerable_network_handler();
    print_status((unsigned long)"Finished ");
    return 0;
}

/*
 * print_status
 * - Prints a status message when non-zero parameter is provided.
 * - Intentionally retains the original printf usage pattern.
 */
unsigned long print_status(unsigned long value)
{
    unsigned int ret;

    if (value != 0) {
        /* Note: format string usage preserved exactly */
        ret = printf("%s\n");
        value = (unsigned long)ret;
    }
    return value;
}