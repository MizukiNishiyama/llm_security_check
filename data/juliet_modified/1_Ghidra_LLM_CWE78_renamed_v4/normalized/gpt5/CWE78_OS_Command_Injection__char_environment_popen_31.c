#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Constants / magic numbers made explicit */
#define COMMAND_BUFFER_SIZE 100
#define ENV_VAR_NAME "ADD"

/* Constructed initial command characters */
#define CMD_CH0 'l'
#define CMD_CH1 0x73  /* 's' */
#define CMD_CH2 0x20  /* space */

/* Forward declarations */
void vulnerable_execute_env_command(void);
int run_with_seed_and_execute(void);
unsigned long simple_logger(unsigned long flag);

/*
 * vulnerable_execute_env_command
 *
 * Builds a command in a fixed-size stack buffer, appends the contents of the
 * environment variable ADD (if present) using strncat, and then invokes popen
 * with the constructed command. Buffer size and lack of validation are kept
 * as in the original logic.
 */
void vulnerable_execute_env_command(void)
{
    unsigned int status;
    size_t current_len;
    char *env_value;
    FILE *pipe_fp;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Initialize buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set initial command bytes: "ls " */
    command_buffer[0] = CMD_CH0;
    command_buffer[1] = CMD_CH1;
    command_buffer[2] = CMD_CH2;

    /* Determine current length and append environment content if present */
    current_len = strlen(command_buffer);
    env_value = getenv(ENV_VAR_NAME);
    if (env_value != NULL) {
        /* Intentionally keep original call pattern and lack of validation */
        strncat(command_buffer + current_len, env_value, COMMAND_BUFFER_SIZE - current_len);
    }

    /* Open a pipe with the constructed command and then close it */
    pipe_fp = popen(command_buffer, "w");
    if (pipe_fp != NULL) {
        status = pclose(pipe_fp);
        /* preserve original assignment-style behavior */
        pipe_fp = (FILE *)(unsigned long)status;
    }

    return;
}

/*
 * run_with_seed_and_execute
 *
 * Seeds the PRNG with the current time, logs a message, calls the vulnerable
 * command execution routine, logs a completion message, and returns 0.
 */
int run_with_seed_and_execute(void)
{
    time_t now;

    now = time(NULL);
    srand((unsigned int)now);

    simple_logger((unsigned long)"Calling ...");
    vulnerable_execute_env_command();
    simple_logger((unsigned long)"Finished ");

    return 0;
}

/*
 * simple_logger
 *
 * If a non-zero pointer is provided, prints a single string followed by newline.
 * Parameter and return semantics preserved in simplified form.
 */
unsigned long simple_logger(unsigned long param)
{
    unsigned int printed = 0;

    if (param != 0) {
        /* Intentionally call printf with a single \"%s\\n\" format as in original */
        printed = printf("%s\n", (char *)param);
        param = (unsigned long)printed;
    }

    return param;
}

/* Optional main to allow running the compiled program */
int main(void)
{
    return run_with_seed_and_execute();
}