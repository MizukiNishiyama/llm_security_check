#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* Constants for readability */
#define BUF_SIZE 100
#define FILE_PATH "/tmp/file.txt"
#define MODE_READ "r"
#define MODE_WRITE "w"
#define GLOBAL_FLAG_VALUE 5

/* Global that mirrors the original binary's global check */
int DAT_100008000 = GLOBAL_FLAG_VALUE;

/* Stack protector symbols referenced similarly to the original binary */
extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* Forward declarations with meaningful names */
void vulnerable_process(void);
int main_flow(void);
unsigned long log_action(unsigned long param);

/* 
 * vulnerable_process:
 * - Builds a small command prefix in command_buffer ("ls ")
 * - Attempts to append contents read from FILE_PATH into the buffer via fgets
 * - Invokes popen on the resulting command buffer and then pclose
 * Note: Buffer sizes, lack of validation, and use of popen are intentionally unchanged.
 */
void vulnerable_process(void)
{
    uint32_t pclose_status;
    size_t prefix_len;
    FILE *fp;
    char *fgets_ret;
    char command_buffer[BUF_SIZE];
    long stack_guard_local;

    /* preserve stack guard value as in original */
    stack_guard_local = __stack_chk_guard;

    /* initialize buffer */
    memset(command_buffer, 0, BUF_SIZE);

    /* build small command prefix: "ls " */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    command_buffer[3] = '\0';

    /* if global flag matches and there is room, attempt to read from FILE_PATH */
    if ((DAT_100008000 == 5) &&
        ((prefix_len = strlen(command_buffer)), 1 < (int)(BUF_SIZE - prefix_len)) &&
        (fp = fopen(FILE_PATH, MODE_READ), fp != NULL)) {
        /* read additional data into command_buffer after the prefix */
        fgets_ret = fgets(command_buffer + prefix_len, (int)(BUF_SIZE - prefix_len), fp);
        if (fgets_ret == NULL) {
            /* original called func_2("fgets() failed"); keep same call pattern */
            log_action((unsigned long)"fgets() failed");
            /* restore null terminator at the original prefix length */
            command_buffer[prefix_len] = '\0';
        }
        fclose(fp);
    }

    /* execute the constructed command via popen, matching original behavior */
    fp = popen(command_buffer, MODE_WRITE);
    if (fp != NULL) {
        pclose_status = pclose(fp);
        /* cast to FILE* as in original to pass to __stack_chk_fail if needed */
        fp = (FILE *)(uintptr_t)pclose_status;
    }

    /* stack check and potential failure call preserved */
    if (__stack_chk_guard == stack_guard_local) {
        return;
    }

    __stack_chk_fail();
}

/*
 * main_flow:
 * - Seeds PRNG with current time
 * - Logs start/finish messages around calling vulnerable_process
 * Behavior mirrors original; return value preserved.
 */
int main_flow(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);

    log_action((unsigned long)"Calling ...");
    vulnerable_process();
    log_action((unsigned long)"Finished ");

    return 0;
}

/*
 * log_action:
 * - If param is non-zero, attempts to print a fixed format string using printf
 * - The original used printf("%s\n") without providing the corresponding argument.
 *   That behavior is preserved exactly here.
 */
unsigned long log_action(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        ret = printf("%s\n");
        param = (unsigned long)ret;
    }
    return param;
}

/* Provide a simple main that calls main_flow to allow standalone compilation */
int main(void)
{
    return main_flow();
}