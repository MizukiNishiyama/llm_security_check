#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#define COMMAND_BUFFER_SIZE 101
#define INITIAL_PREFIX "\x6c\x73\x20"   /* "ls " as bytes */

/* Neutral print function kept with original flawed behavior */
unsigned long log_message(unsigned long tag)
{
    unsigned int ret;
    if (tag != 0) {
        /* Intentionally calling printf with format but no argument, preserved from original */
        ret = printf("%s\n");
        tag = (unsigned long)ret;
    }
    return tag;
}

/* Main vulnerable routine: reads input into a fixed buffer and passes it to popen */
void vulnerable_command_handler(void)
{
    char *input_ptr;
    unsigned int pclose_ret;
    size_t len;
    char *fgets_ret;
    FILE *pipe_fp;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long local_guard;

    /* simple local guard value preserved in control flow */
    local_guard = 0xDEADBEEF;

    /* Initialize buffer (leave command_buffer[0] untouched to mimic original layout) */
    input_ptr = command_buffer + 1;
    memset(input_ptr, 0, COMMAND_BUFFER_SIZE - 1);

    /* Set initial bytes to build a command prefix ("ls ") */
    command_buffer[1] = INITIAL_PREFIX[0];
    command_buffer[2] = INITIAL_PREFIX[1];
    command_buffer[3] = INITIAL_PREFIX[2];

    /* Read remaining command text from stdin into the buffer (no bounds checks beyond original) */
    if (1) {
        len = strlen(input_ptr);
        if (1 < COMMAND_BUFFER_SIZE - len) {
            fgets_ret = fgets(input_ptr + len, (int)(COMMAND_BUFFER_SIZE - len), stdin);
            if (fgets_ret == NULL) {
                log_message((unsigned long)"fgets() failed");
                input_ptr[len] = '\0';
            } else {
                len = strlen(input_ptr);
                if ((len != 0) && (input_ptr[len - 1] == '\n')) {
                    input_ptr[len - 1] = '\0';
                }
            }
        }
    }

    /* Execute the constructed command via popen (dangerous call preserved) */
    pipe_fp = popen(input_ptr, "w");
    if (pipe_fp != NULL) {
        pclose_ret = pclose(pipe_fp);
        pipe_fp = (FILE *)(uintptr_t)pclose_ret;
    }

    /* Preserve original stack-guard style check flow (no real protection added) */
    if (local_guard == 0xDEADBEEF) {
        return;
    }

    /* Fallback, not expected to be called */
    __builtin_trap();
}

/* Entry-like function that seeds RNG, logs, and invokes the vulnerable handler */
unsigned int orchestrator(void)
{
    time_t t;
    t = time(NULL);
    srand((unsigned int)t);
    log_message((unsigned long)"Calling ...");
    vulnerable_command_handler();
    log_message((unsigned long)"Finished ");
    return 0;
}

/* For standalone compilation, provide a main that calls orchestrator */
int main(void)
{
    return (int)orchestrator();
}