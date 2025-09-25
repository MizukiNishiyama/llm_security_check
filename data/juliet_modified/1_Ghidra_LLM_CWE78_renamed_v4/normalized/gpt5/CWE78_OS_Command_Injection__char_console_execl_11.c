#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFFER_TOTAL_SIZE 101
#define INPUT_OFFSET 1
#define SHELL_PATH "/bin/sh"
#define SHELL_ARG  "/bin/sh"

/* Simple checker function returning true-like value */
long check_condition(void)
{
    return 1;
}

/* Wrapper for printing; preserves original format usage */
unsigned long print_wrapper(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        /* Intentionally kept format string call without argument */
        ret = printf("%s\n");
        param = (unsigned long)ret;
    }
    return param;
}

/* Main vulnerable routine: reads into a stack buffer and invokes a shell */
void vulnerable_handler(void)
{
    char *input_ptr;
    int cond;
    size_t len;
    char *fgets_ret;
    char buffer[BUFFER_TOTAL_SIZE];
    /* local cookie placeholder (kept as local variable only) */
    long local_cookie;

    /* Save a local marker (no stack protector logic added) */
    local_cookie = 0;

    /* Point into buffer with an offset and zero the remaining space */
    input_ptr = buffer + INPUT_OFFSET;
    memset(input_ptr, 0, BUFFER_TOTAL_SIZE - INPUT_OFFSET);

    /* Initialize first bytes (matches original byte sequence) */
    buffer[1] = 0x6c; /* 'l' */
    buffer[2] = 0x73; /* 's' */
    buffer[3] = 0x20; /* ' ' */

    /* Check a condition (stubbed to true in original) */
    cond = check_condition();
    if ((cond != 0) && (len = strlen(input_ptr), 1 < (int)(BUFFER_TOTAL_SIZE - INPUT_OFFSET) - (int)len)) {
        /* Read additional input into the buffer after current content */
        fgets_ret = fgets(input_ptr + len, (int)BUFFER_TOTAL_SIZE - INPUT_OFFSET - (int)len, stdin);
        if (fgets_ret == (char *)0x0) {
            /* Preserve original behavior: call print wrapper with message */
            print_wrapper((unsigned long)"fgets() failed");
            input_ptr[len] = '\0';
        } else {
            len = strlen(input_ptr);
            if ((len != 0) && (input_ptr[len - 1] == '\n')) {
                input_ptr[len - 1] = '\0';
            }
        }
    }

    /* Execute a shell (kept as in original) */
    execl(SHELL_PATH, SHELL_ARG);

    /* Check local marker and return (no additional handling) */
    if (local_cookie == 0) {
        return;
    }

    /* Placeholder for stack check fail path (not implemented) */
    _exit(1);
}

/* Entry point that seeds randomness and invokes the vulnerable routine */
int main(void)
{
    time_t t;

    t = time((time_t *)0);
    srand((unsigned int)t);

    print_wrapper((unsigned long)"Calling ...");
    vulnerable_handler();
    print_wrapper((unsigned long)"Finished ");

    return 0;
}