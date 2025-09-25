#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* Minimal externs to mirror original stack protector checks */
extern long __stack_chk_guard;
extern void __stack_chk_fail(int);

/* Constants for clarity */
#define COMMAND_BUFFER_SIZE 100

/* Global flag that controls file read behavior (kept as in original) */
int data_flag = 0;

/* Forward declarations with meaningful names */
char *read_append_from_file(char *buffer);
int vulnerable_entry(void);
unsigned long log_message(unsigned long msg);
unsigned int driver_main(void);

/* Main vulnerable entry: prepares command buffer and invokes shell */
int vulnerable_entry(void)
{
    int ret_val;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long saved_canary;

    /* preserve stack protector value (mirrors original behavior) */
    saved_canary = __stack_chk_guard;

    /* initialize buffer to zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* set initial bytes to "ls " as in original */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* set global flag and attempt to append data from file */
    data_flag = 1;
    read_append_from_file(command_buffer);

    /* call exec to invoke a shell (kept unsafe as in original) */
    ret_val = execl("/bin/sh", "/bin/sh");

    /* stack protector check (kept as in original) */
    if (__stack_chk_guard != saved_canary) {
        __stack_chk_fail(ret_val);
    }

    return 0;
}

/* Attempts to append contents of /tmp/file.txt into provided buffer */
char *read_append_from_file(char *buffer)
{
    size_t current_len;
    FILE *fp;
    char *res;

    /* If the global flag is set and there is space, open and read from file */
    if ((data_flag != 0) &&
        ((current_len = strlen(buffer)), (1 < (COMMAND_BUFFER_SIZE - current_len))) &&
        ((fp = fopen("/tmp/file.txt", "r")) != NULL)) {

        /* read into the buffer at the current end (no bounds checks beyond original) */
        res = fgets(buffer + current_len, COMMAND_BUFFER_SIZE - (int)current_len, fp);
        if (res == NULL) {
            /* preserve original behavior: call logger and terminate the string */
            log_message((unsigned long)"fgets() failed");
            buffer[current_len] = '\0';
        }
        fclose(fp);
    }

    return buffer;
}

/* Initializes randomness, logs, and calls the vulnerable entry */
unsigned int driver_main(void)
{
    time_t t;
    t = time((time_t *)0);
    srand((unsigned int)t);

    log_message((unsigned long)"Calling ...");
    vulnerable_entry();
    log_message((unsigned long)"Finished ");

    return 0;
}

/* Simple logging function that prints a string if provided */
unsigned long log_message(unsigned long msg)
{
    unsigned int printed = 0;
    if (msg != 0) {
        /* original used printf("%s\n") without explicit argument; keep a similar call
           but provide the msg pointer to maintain clarity for LLMs */
        printed = printf("%s\n", (const char *)msg);
        msg = (unsigned long)printed;
    }
    return msg;
}