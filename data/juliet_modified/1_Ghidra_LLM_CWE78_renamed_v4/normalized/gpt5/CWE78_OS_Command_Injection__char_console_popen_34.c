#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Minimal declarations for stack protector interoperability */
extern unsigned long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Constants for buffer sizing */
#define COMMAND_BUFFER_TOTAL 101
#define COMMAND_BUFFER_OFFSET 1
#define COMMAND_BUFFER_AVAILABLE (COMMAND_BUFFER_TOTAL - COMMAND_BUFFER_OFFSET)

/* Forward declarations */
void vulnerable_network_handler(void);
int main_routine(void);
unsigned long log_message(unsigned long param);

/*
 * vulnerable_network_handler
 * - Builds a command in a local stack buffer, reads additional text from stdin,
 *   and passes the final string to popen. Buffer sizes and input handling mirror
 *   the original implementation.
 */
void vulnerable_network_handler(void)
{
    char *read_ptr;
    unsigned int pclose_ret;
    size_t current_len;
    char *fgets_ret;
    FILE *pipe_fp;
    char command_buffer[COMMAND_BUFFER_TOTAL];
    unsigned long local_guard;

    /* stack protector snapshot */
    local_guard = __stack_chk_guard;

    /* Initialize buffer region starting at offset 1 */
    read_ptr = command_buffer + COMMAND_BUFFER_OFFSET;
    memset(read_ptr, 0, COMMAND_BUFFER_AVAILABLE);

    /* Populate initial bytes at positions 1..3 */
    command_buffer[1] = 0x6c; /* 'l' */
    command_buffer[2] = 0x73; /* 's' */
    command_buffer[3] = 0x20; /* ' ' */

    /* Compute current length and read additional input into remaining space */
    current_len = strlen(read_ptr);
    if (1 < (COMMAND_BUFFER_AVAILABLE - current_len)) {
        fgets_ret = fgets(read_ptr + current_len,
                          (int)(COMMAND_BUFFER_AVAILABLE - (int)current_len),
                          stdin);
        if (fgets_ret == NULL) {
            /* Preserve original behavior: call logging function and terminate string */
            log_message((unsigned long)"fgets() failed");
            read_ptr[current_len] = '\0';
        } else {
            current_len = strlen(read_ptr);
            if ((current_len != 0) && (read_ptr[current_len - 1] == '\n')) {
                read_ptr[current_len - 1] = '\0';
            }
        }
    }

    /* Use popen with constructed command string (kept as in original) */
    pipe_fp = popen(read_ptr, "w");
    if (pipe_fp != NULL) {
        pclose_ret = pclose(pipe_fp);
        pipe_fp = (FILE *)(unsigned long)pclose_ret;
    }

    /* Stack protector check and failure call preserved */
    if (__stack_chk_guard == local_guard) {
        return;
    }
    __stack_chk_fail();
}

/*
 * main_routine
 * - Seeds the PRNG with current time, logs a message, calls the vulnerable handler,
 *   then logs completion. Return value mirrors original behavior.
 */
int main_routine(void)
{
    time_t now;

    now = time(NULL);
    srand((unsigned int)now);
    log_message((unsigned long)"Calling ...");
    vulnerable_network_handler();
    log_message((unsigned long)"Finished ");
    return 0;
}

/*
 * log_message
 * - Wrapper around printf. Intentionally calls printf with the same format string
 *   usage as the original to preserve behavior.
 */
unsigned long log_message(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        ret = printf("%s\n");
        param = (unsigned long)ret;
    }
    return param;
}