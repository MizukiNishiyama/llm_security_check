#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* Constants for readability (preserve original sizes/limits) */
#define COMMAND_BUFFER_SIZE 100
#define MAX_CONCAT_LEN (COMMAND_BUFFER_SIZE - 1)

/* External stack protector symbols (kept to mirror original control flow) */
extern uintptr_t __stack_chk_guard;
void __stack_chk_fail(void *);

/* Rename of func_0: builds a command buffer and executes it via popen */
void vulnerable_command_executor(void)
{
    size_t current_len;
    char *env_value;
    FILE *pipe_stream;
    char command_buffer[COMMAND_BUFFER_SIZE];
    uintptr_t saved_stack_guard;

    /* preserve original stack guard check behavior */
    saved_stack_guard = __stack_chk_guard;

    /* initialize command buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* original initialization: 'l', 's', ' ' -> "ls " */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* compute current length and append environment content if present */
    current_len = strlen(command_buffer);
    env_value = getenv("ADD");
    if (env_value != NULL) {
        /* intentionally preserve lack of bounds/validation checks */
        strncat(command_buffer + current_len, env_value, MAX_CONCAT_LEN - current_len);
    }

    /* execute constructed command using popen with mode "w" (kept as original) */
    pipe_stream = popen(command_buffer, "w");
    if (pipe_stream != NULL) {
        unsigned int rc = pclose(pipe_stream);
        /* cast to FILE* to mirror original style when passing to stack check fail */
        pipe_stream = (FILE *)(uintptr_t)rc;
    }

    /* stack protector check (kept as original control flow) */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail(pipe_stream);
    }

    return;
}

/* Rename of func_2: prints a message when param is non-zero (keeps original call pattern) */
unsigned long print_message(unsigned long flag)
{
    unsigned int ret;

    if (flag != 0) {
        /* original code called printf with "%s\n" but no argument */
        /* preserved as-is to keep original behavior */
        ret = printf("%s\n");
        flag = (unsigned long)ret;
    }
    return flag;
}

/* Rename of func_1: seeds RNG, prints messages and calls the vulnerable executor */
unsigned int run_sequence(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);

    print_message((unsigned long)"Calling ...");
    vulnerable_command_executor();
    print_message((unsigned long)"Finished ");

    return 0;
}

/* Optional entry point to allow compilation/execution */
int main(void)
{
    return (int)run_sequence();
}