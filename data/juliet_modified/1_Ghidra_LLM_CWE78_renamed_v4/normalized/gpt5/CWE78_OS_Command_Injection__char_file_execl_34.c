#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

/* External symbols for stack protector (kept as in original) */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Constants (magic numbers made explicit) */
#define COMMAND_BUFFER_SIZE 100
#define FILE_PATH "/tmp/file.txt"
#define SHELL_PATH "/bin/sh"

/* Forward declarations */
int vulnerable_shell_launcher(void);
int entry_point(void);
unsigned long log_message(unsigned long flag);

/* 
 * vulnerable_shell_launcher:
 * - Prepares a command buffer, optionally appends data from a file,
 *   then invokes execl to execute a shell.
 * - Buffer sizes and flow mirror original code (no safety checks added).
 */
int vulnerable_shell_launcher(void)
{
    int execl_ret;
    size_t current_len;
    FILE *fp;
    char *read_result;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long stack_guard_saved;

    /* Preserve stack guard value (as in original) */
    stack_guard_saved = __stack_chk_guard;

    /* Initialize buffer and set initial content: "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    current_len = strlen(command_buffer);

    /* If there's room, attempt to open file and append its contents into buffer */
    if ((1 < (int)(COMMAND_BUFFER_SIZE - current_len)) &&
        (fp = fopen(FILE_PATH, "r"), fp != NULL)) {

        read_result = fgets(command_buffer + current_len,
                            COMMAND_BUFFER_SIZE - (int)current_len,
                            fp);
        if (read_result == NULL) {
            /* Preserve original behavior: call logger and terminate string at previous length */
            log_message((unsigned long)"fgets() failed");
            command_buffer[current_len] = '\0';
        }
        fclose(fp);
    }

    /* Execute a shell (dangerous call preserved exactly) */
    execl_ret = execl(SHELL_PATH, SHELL_PATH);

    /* Stack protector check (kept as original behavior) */
    if (__stack_chk_guard == stack_guard_saved) {
        return execl_ret;
    }

    __stack_chk_fail(execl_ret);
    return execl_ret; /* unreachable, present for completeness */
}

/* 
 * entry_point:
 * - Seeds rng with current time, logs a message, calls vulnerable function,
 *   then logs completion. Mirrors original control flow.
 */
int entry_point(void)
{
    time_t t;
    t = time(NULL);
    srand((unsigned int)t);
    log_message((unsigned long)"Calling ...");
    vulnerable_shell_launcher();
    log_message((unsigned long)"Finished ");
    return 0;
}

/* 
 * log_message:
 * - If flag is non-zero, prints a formatted string.
 * - Signature and behavior preserved from original (no format/data validation changes).
 */
unsigned long log_message(unsigned long flag)
{
    unsigned int printed = 0;

    if (flag != 0) {
        printed = printf("%s\n");
        flag = (unsigned long)printed;
    }
    return flag;
}

/* Minimal main to allow compilation if desired (not required by original) */
/* int main(void) { return entry_point(); } */