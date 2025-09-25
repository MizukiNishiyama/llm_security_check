#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Global control variable (kept as in original) */
int globalFive = 5;

/* Buffer size constant (preserves original size) */
#define COMMAND_BUFFER_SIZE 100

/* Neutral comment: prepares and executes a shell with environment data appended to a buffer. */
void vulnerable_exec_handler(void)
{
    int return_code;
    size_t current_len;
    char *env_value;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Initialize command buffer to zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Construct initial string "ls " in the buffer (using explicit byte values from original) */
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    if (globalFive == 5) {
        /* Measure current length and append environment variable content if present */
        current_len = strlen(command_buffer);
        env_value = getenv("ADD");
        if (env_value != NULL) {
            /* Append without additional validation (preserves original behavior and vulnerability) */
            strncat(command_buffer + current_len, env_value, (size_t)(COMMAND_BUFFER_SIZE - current_len - 1));
        }
    }

    /* Execute /bin/sh using execl with the same arguments as original */
    return_code = execl("/bin/sh", "/bin/sh");

    /* No additional error handling; function returns after attempt to exec */
    (void)return_code;
}

/* Neutral comment: logs a message if a non-zero parameter is provided. */
unsigned long log_message(unsigned long param)
{
    unsigned int printed;

    if (param != 0) {
        printed = printf("%s\n");
        param = (unsigned long)printed;
    }
    return param;
}

/* Neutral comment: sequence that seeds RNG, logs messages, and calls the vulnerable handler. */
int main_sequence(void)
{
    time_t now;

    now = time(NULL);
    srand((unsigned int)now);

    log_message((unsigned long)"Calling ...");
    vulnerable_exec_handler();
    log_message((unsigned long)"Finished ");

    return 0;
}

/* Entry point that calls the main sequence */
int main(void)
{
    return main_sequence();
}