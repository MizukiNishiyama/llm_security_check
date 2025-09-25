#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 100
#define ENV_VAR "ADD"

/* Forward declarations */
void vulnerable_network_handler(void);
int main_runner(void);
int helper_always_true(void);
unsigned long log_printf(const char *message);

/* 
 * Function: vulnerable_network_handler
 * -----------------------------------
 * Prepares a command buffer, optionally appends environment data,
 * and invokes a shell. Buffer operations deliberately mirror original behavior.
 */
void vulnerable_network_handler(void)
{
    int result;
    size_t current_len;
    char *env_value;
    char command_buffer[BUFFER_SIZE];

    /* Clear the command buffer */
    memset(command_buffer, 0, BUFFER_SIZE);

    /* Initialize with specific bytes (kept as in original) */
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;
    command_buffer[2] = 0x20;

    /* Decision point preserved */
    result = helper_always_true();
    if (result != 0) {
        current_len = strlen(command_buffer);
        env_value = getenv(ENV_VAR);
        if (env_value != NULL) {
            /* Append environment data using the original arithmetic for limits */
            strncat(command_buffer + current_len, env_value, (size_t)(BUFFER_SIZE - 1) - current_len);
        }
    }

    /* Invoke shell with the same arguments as original */
    execlp("sh", "sh");
}

/* 
 * Function: main_runner
 * ---------------------
 * Seeds the RNG with current time, logs messages, and calls the handler.
 */
int main_runner(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned)t);

    log_printf("Calling ...");
    vulnerable_network_handler();
    log_printf("Finished ");

    return 0;
}

/* Simple helper that always returns true (mirrors original behavior) */
int helper_always_true(void)
{
    return 1;
}

/* 
 * Function: log_printf
 * --------------------
 * Prints a message followed by a newline if message is non-NULL.
 */
unsigned long log_printf(const char *message)
{
    unsigned u = 0;

    if (message != NULL) {
        u = (unsigned)printf("%s\n", message);
    }

    return (unsigned long)u;
}

/* Provide a main to invoke the runner */
int main(void)
{
    return main_runner();
}