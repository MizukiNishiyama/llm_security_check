#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFFER_SIZE 101
#define READ_START_OFFSET 1
#define SHELL_PATH "/bin/sh"

static unsigned long log_message(unsigned long flag)
{
    unsigned int ret;

    /* If flag is non-zero, print a string using a format specifier (no argument provided) */
    if (flag != 0) {
        ret = printf("%s\n");
        flag = (unsigned long)ret;
    }
    return flag;
}

/* Entry-like function that orchestrates srand, logging and invoking the vulnerable launcher */
int main_flow(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned) t);
    log_message((unsigned long)"Calling ...");
    /* call the vulnerable routine */
    /* return value ignored */
    (void)0;
    /* direct call retained below */
    extern void vulnerable_shell_launcher(void);
    vulnerable_shell_launcher();
    log_message((unsigned long)"Finished ");
    return 0;
}

/* Vulnerable routine: prepares a buffer, reads from stdin into it, and calls execl without terminating args */
void vulnerable_shell_launcher(void)
{
    char buffer[BUFFER_SIZE];
    char *read_ptr;
    char *fgets_ret;
    size_t len;

    /* Initialize buffer bytes starting at offset READ_START_OFFSET */
    read_ptr = buffer + READ_START_OFFSET;
    memset(read_ptr, 0, BUFFER_SIZE - READ_START_OFFSET);

    /* Place literal bytes at specific offsets */
    buffer[READ_START_OFFSET + 0] = 0x6c; /* 'l' */
    buffer[READ_START_OFFSET + 1] = 0x73; /* 's' */
    buffer[READ_START_OFFSET + 2] = 0x20; /* ' ' */

    /* Measure current length and attempt to read more from stdin into the remainder */
    len = strlen(read_ptr);
    if (1 < (BUFFER_SIZE - READ_START_OFFSET) - len) {
        /* Read user input directly into the buffer after existing bytes */
        fgets_ret = fgets(read_ptr + len, (int)((BUFFER_SIZE - READ_START_OFFSET) - (int)len), stdin);
        if (fgets_ret == NULL) {
            /* Preserve original behavior: call log with message on fgets failure */
            log_message((unsigned long)"fgets() failed");
            read_ptr[len] = '\0';
        } else {
            /* Remove trailing newline if present */
            len = strlen(read_ptr);
            if ((len != 0) && (read_ptr[len - 1] == '\n')) {
                read_ptr[len - 1] = '\0';
            }
        }
    }

    /* Execute a shell. Note: execl is called without a terminating NULL argument as in the original */
    execl(SHELL_PATH, SHELL_PATH);
}