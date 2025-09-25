#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Constants */
#define COMMAND_BUFFER_SIZE 100
#define INPUT_FILE_PATH "/tmp/file.txt"
#define POPEN_MODE "w"

/* External stack protector symbols (preserve original stack-check behavior) */
extern unsigned long __stack_chk_guard;
void __stack_chk_fail(void *);

/* Function prototypes */
void vulnerable_command_executor(void);
int main_wrapper(void);
unsigned long logger(unsigned long param);

/*
 * vulnerable_command_executor:
 * - Builds a command prefix in a fixed-size buffer
 * - Attempts to append contents from a file into the buffer using fgets
 * - Passes the buffer directly to popen with mode "w"
 *
 * Note: Buffer sizes, I/O calls and control flow are intentionally left as in the original.
 */
void vulnerable_command_executor(void)
{
    unsigned int status;
    size_t prefix_len;
    FILE *file;
    char *fgets_ret;
    char command_buffer[COMMAND_BUFFER_SIZE];
    unsigned long saved_stack = __stack_chk_guard;

    /* Initialize buffer and set a short command prefix "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    prefix_len = strlen(command_buffer);

    /* If there is room, try to read additional data from a file into the buffer */
    if ((1 < COMMAND_BUFFER_SIZE - prefix_len) &&
        (file = fopen(INPUT_FILE_PATH, "r"), file != NULL)) {

        fgets_ret = fgets(command_buffer + prefix_len,
                          COMMAND_BUFFER_SIZE - (int)prefix_len,
                          file);

        if (fgets_ret == NULL) {
            /* Preserve original behavior: call logger and terminate the read by resetting terminator */
            logger((unsigned long)"fgets() failed");
            command_buffer[prefix_len] = '\0';
        }

        fclose(file);
    }

    /* Pass the (possibly tainted) command buffer to popen with mode "w" */
    file = popen(command_buffer, POPEN_MODE);
    if (file != NULL) {
        status = pclose(file);
        file = (FILE *)(unsigned long)status;
    }

    /* Stack protector check preserved */
    if (__stack_chk_guard == saved_stack) {
        return;
    }

    __stack_chk_fail(file);
}

/*
 * main_wrapper:
 * - Seeds PRNG with current time
 * - Logs and invokes the vulnerable executor
 */
int main_wrapper(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);

    logger((unsigned long)"Calling ...");
    vulnerable_command_executor();
    logger((unsigned long)"Finished ");

    return 0;
}

/*
 * logger:
 * - If param is non-zero, calls printf with a format string only (preserve original call pattern)
 * - Returns the numeric result
 *
 * Note: The call pattern here mirrors the original and may lead to undefined behavior.
 */
unsigned long logger(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        ret = printf("%s\n");
        param = (unsigned long)ret;
    }

    return param;
}

/* Provide a main that calls the wrapper to match original usage */
int main(void)
{
    return main_wrapper();
}