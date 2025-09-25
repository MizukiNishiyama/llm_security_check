#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* Constants (magic numbers made explicit) */
#define INPUT_BUF_SIZE 101
#define INPUT_OFFSET 1

/* External stack protector symbols (kept as in original control flow) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(int);

/* Function prototypes */
void vulnerable_command_handler(void);
int entry_point(void);
unsigned long log_message(unsigned long param);

/* Read user input after a preset prefix and attempt to execute a shell.
   Note: buffer sizes and unsafe calls intentionally preserved. */
void vulnerable_command_handler(void)
{
    char *read_ptr;
    int exec_ret;
    size_t len;
    char *fret;
    char input_buffer[INPUT_BUF_SIZE];
    long stack_chk_local;

    /* stack protector snapshot */
    stack_chk_local = __stack_chk_guard;

    /* Prepare buffer: start writing at offset 1 */
    read_ptr = input_buffer + INPUT_OFFSET;

    /* Clear remaining bytes */
    memset(read_ptr, 0, INPUT_BUF_SIZE - INPUT_OFFSET);

    /* Insert a fixed prefix at the beginning of the usable buffer */
    input_buffer[1] = 0x6c; /* 'l' */
    input_buffer[2] = 0x73; /* 's' */
    input_buffer[3] = 0x20; /* ' ' */

    /* Conditional block mimicking original control flow */
    if (5 == 5) {
        len = strlen(read_ptr);

        /* Keep original boundary logic (no additional validation) */
        if (1 < (INPUT_BUF_SIZE - INPUT_OFFSET) - len) {
            fret = fgets(read_ptr + len, (int)((INPUT_BUF_SIZE - INPUT_OFFSET) - len), stdin);
            if (fret == NULL) {
                /* Preserve original behavior of logging on fgets failure */
                log_message((unsigned long)"fgets() failed");
                read_ptr[len] = '\0';
            } else {
                len = strlen(read_ptr);
                if ((len != 0) && (read_ptr[len - 1] == '\n')) {
                    read_ptr[len - 1] = '\0';
                }
            }
        }
    }

    /* Dangerous call preserved exactly as in original */
    exec_ret = execl("/bin/sh", "/bin/sh");

    /* Check stack protector and call fail handler if altered */
    if (__stack_chk_guard == stack_chk_local) {
        return;
    }

    __stack_chk_fail(exec_ret);
}

/* Entry function: seeds RNG, logs, calls vulnerable handler, logs again */
int entry_point(void)
{
    time_t t;
    t = time((time_t *)0);
    srand((unsigned int)t);
    log_message((unsigned long)"Calling ...");
    vulnerable_command_handler();
    log_message((unsigned long)"Finished ");
    return 0;
}

/* Logging helper: preserves original printf misuse (format string with no argument) */
unsigned long log_message(unsigned long param)
{
    unsigned int u;

    if (param != 0) {
        u = printf("%s\n");
        param = (unsigned long)u;
    }
    return param;
}