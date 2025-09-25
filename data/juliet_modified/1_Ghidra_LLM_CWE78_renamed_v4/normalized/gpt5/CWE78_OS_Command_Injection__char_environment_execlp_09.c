#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define COMMAND_BUFFER_SIZE 100

/* Neutral comments describing processing steps only */

/* Builds a command buffer from a fixed prefix and an environment variable,
   then spawns a shell. Vulnerable behavior and dangerous calls are preserved. */
void vulnerable_spawn_shell(void)
{
    int exec_result;
    size_t prefix_len;
    char *env_add;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* initialize buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;  /* 's' */
    command_buffer[2] = ' ';

    /* append contents of environment variable "ADD" to the buffer */
    prefix_len = strlen(command_buffer);
    env_add = getenv("ADD");
    if (env_add != NULL) {
        /* replicate original use of strncat with destination pointer offset */
        strncat(command_buffer + prefix_len, env_add,
                (size_t)(COMMAND_BUFFER_SIZE - 1 - prefix_len));
    }

    /* execute shell (call left unchanged) */
    exec_result = execlp("sh", "sh");
    (void)exec_result; /* preserve original control flow; no error handling added */
}

/* Logs a message. The printf call mirrors the original (no argument passed). */
unsigned long log_message(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        /* Intentionally mirrors original call signature where printf is invoked
           without providing the expected argument. */
        ret = printf("%s\n");
        param = (unsigned long)ret;
    }
    return param;
}

/* Orchestrator similar to original: seeds RNG, logs, invokes vulnerable routine */
int orchestrator(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);
    log_message((unsigned long)"Calling ...");
    vulnerable_spawn_shell();
    log_message((unsigned long)"Finished ");
    return 0;
}

/* Entry point */
int main(void)
{
    return orchestrator();
}