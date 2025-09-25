#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* Constants extracted from magic numbers */
#define BUFFER_SIZE 100
#define TEMP_FILE_PATH "/tmp/file.txt"
#define SHELL_PATH "/bin/sh"

/* Forward declarations */
void vulnerable_network_handler(void);
int main_like(void);
int check_condition(void);
unsigned long log_message(unsigned long param);

/* Stack protector symbols (kept for original control-flow) */
extern void __stack_chk_fail(long);
extern unsigned long __stack_chk_guard;

/* Implementation */

/* 
 * vulnerable_network_handler
 * - Prepares a command buffer, optionally appends data from a temporary file,
 *   and then invokes execl to run a shell.
 * - Buffer sizes and behavior preserved from original implementation.
 */
void vulnerable_network_handler(void)
{
    int ret;
    size_t current_len;
    FILE *file;
    char *read_result;
    char command_buffer[BUFFER_SIZE];
    unsigned long saved_guard = __stack_chk_guard;

    /* Initialize buffer to zeros and set initial content ("ls ") */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    /* Note: no bounds checks beyond original logic are added */

    ret = check_condition();
    if ((ret != 0) && ((current_len = strlen(command_buffer)), 1 < (BUFFER_SIZE - current_len))) {
        file = fopen(TEMP_FILE_PATH, "r");
        if (file != NULL) {
            /* Read additional data into the buffer starting at current_len */
            read_result = fgets(command_buffer + current_len, (int)(BUFFER_SIZE - current_len), file);
            if (read_result == NULL) {
                /* Preserve original behavior: call log_message and restore string terminator */
                log_message((unsigned long)"fgets() failed");
                command_buffer[current_len] = '\0';
            }
            fclose(file);
        }
    }

    /* Invoke a shell as in the original code; arguments preserved */
    ret = execl(SHELL_PATH, SHELL_PATH);

    /* Stack protector check preserved */
    if (__stack_chk_guard == saved_guard) {
        return;
    }

    __stack_chk_fail(ret);
}

/* 
 * main_like
 * - Seeds RNG with current time, logs, calls the vulnerable handler, logs again.
 */
int main_like(void)
{
    time_t t;
    t = time(NULL);
    srand((unsigned) t);
    log_message((unsigned long)"Calling ...");
    vulnerable_network_handler();
    log_message((unsigned long)"Finished ");
    return 0;
}

/* check_condition
 * - Returns a fixed non-zero value as in the original decompiled code.
 */
int check_condition(void)
{
    return 1;
}

/* log_message
 * - Prints a message if a non-zero parameter is provided.
 * - Behavior mirrors the original: uses printf and returns the printed character count.
 */
unsigned long log_message(unsigned long param)
{
    unsigned int printed = 0;

    if (param != 0) {
        printed = printf("%s\n");
        param = (unsigned long) printed;
    }
    return param;
}

/* Simple main that calls main_like to preserve usual entry point */
int main(void)
{
    return main_like();
}