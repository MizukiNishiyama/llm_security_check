#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* External stack protector symbols (kept for structural parity with original) */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Constants for readability */
#define BUFFER_SIZE 100
#define INITIAL_CMD "ls "
#define ENV_VAR "ADD"

/* Function prototypes with descriptive names */
void vulnerable_command_executor(void);
int run_sequence(void);
unsigned long log_print(unsigned long param);

/* Implementation */

/* Build a command in a fixed-size buffer by concatenating an environment value,
   then invoke a shell using execlp. Buffer sizes and lack of validation are preserved. */
void vulnerable_command_executor(void)
{
    int result;
    size_t current_len;
    char *env_value;
    char command_buffer[BUFFER_SIZE];
    long saved_canary;

    /* save stack guard for later verification */
    saved_canary = __stack_chk_guard;

    /* initialize buffer and place initial command */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    current_len = strlen(command_buffer);

    /* append environment variable content if present (no validation) */
    env_value = getenv(ENV_VAR);
    if (env_value != NULL) {
        /* preserve original concatenation behavior and length parameter */
        strncat(command_buffer + current_len, env_value, (size_t)(BUFFER_SIZE - 1 - current_len));
    }

    /* invoke shell; original argument pattern preserved */
    result = execlp("sh", "sh");

    /* stack check reproduced as in original */
    if (__stack_chk_guard != saved_canary) {
        __stack_chk_fail(result);
    }

    return;
}

/* Seed RNG, print a message, run the vulnerable executor, print another message */
int run_sequence(void)
{
    time_t now;

    now = time(NULL);
    srand((unsigned int)now);

    log_print((unsigned long)"Calling ...");
    vulnerable_command_executor();
    log_print((unsigned long)"Finished ");

    return 0;
}

/* Simple logging helper: prints a string followed by newline if param non-zero */
unsigned long log_print(unsigned long param)
{
    unsigned int printed = 0;

    if (param != 0) {
        printed = printf("%s\n");
    }
    return (unsigned long)printed;
}

/* Optional: map original entry name if needed */
int main(void)
{
    return run_sequence();
}