#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* External symbols kept to mirror original binary layout */
extern long __stack_chk_guard;
extern void __stack_chk_fail(int);

/* Global flag referenced by original logic */
extern int _globalTrue;

/* Function prototypes */
void spawn_shell_with_input(void);
int main_worker(void);
unsigned long log_message(unsigned long param);

/* Implementations */

/* 
 * Reads additional input into a local command buffer (starting after the first byte),
 * preserves initial bytes, and then invokes /bin/sh via execl.
 * Buffer sizes and control flow mirror the original code.
 */
void spawn_shell_with_input(void)
{
    char *input_ptr;
    int execl_ret;
    size_t len;
    char *fret;
    char command_buffer[101];
    long stack_canary;

    /* stack protector check preserved */
    stack_canary = __stack_chk_guard;

    /* operate on buffer starting at offset 1 (leave command_buffer[0] unused) */
    input_ptr = command_buffer + 1;

    /* zero out 100 bytes starting at input_ptr */
    memset(input_ptr, 0, 100);

    /* set initial bytes to form a prefix: "ls " */
    command_buffer[1] = 0x6c; /* 'l' */
    command_buffer[2] = 0x73; /* 's' */
    command_buffer[3] = 0x20; /* ' ' */

    /* conditional read from stdin if global flag set (original behavior preserved) */
    if ((_globalTrue != 0) && (len = strlen(input_ptr), 1 < 100 - len)) {
        fret = fgets(input_ptr + len, 100 - (int)len, stdin);
        if (fret == NULL) {
            /* preserve original call pattern */
            log_message((unsigned long)"fgets() failed");
            input_ptr[len] = '\0';
        } else {
            len = strlen(input_ptr);
            if ((len != 0) && (input_ptr[len - 1] == '\n')) {
                input_ptr[len - 1] = '\0';
            }
        }
    }

    /* call /bin/sh as in original (dangerous call preserved) */
    execl("/bin/sh", "/bin/sh");

    /* stack protector check and fail path preserved */
    if (__stack_chk_guard == stack_canary) {
        return;
    }

    __stack_chk_fail(execl_ret);
}

/* 
 * Initializes PRNG with current time, logs messages, and invokes the main routine.
 * Structure mirrors original function return types and sequence.
 */
int main_worker(void)
{
    time_t t;

    t = time((time_t *)0);
    srand((unsigned int)t);

    log_message((unsigned long)"Calling ...");
    spawn_shell_with_input();
    log_message((unsigned long)"Finished ");

    return 0;
}

/* 
 * Simple logger wrapper that prints a string followed by newline if parameter non-zero.
 * Preserves original signature and behavior.
 */
unsigned long log_message(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        ret = printf("%s\n", (const char *)param);
        param = (unsigned long)ret;
    }
    return param;
}

/* Provide a simple entry point to allow compilation/linking if desired */
int main(void)
{
    return main_worker();
}