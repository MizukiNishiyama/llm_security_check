#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Constants mirroring original magic numbers */
#define COMMAND_BUFFER_SIZE 100

/* Global flag corresponding to original DAT_100008000 */
int global_flag = 0;

/* Forward declarations with clearer names */
char *append_env_add_to_command(char *command);
void vulnerable_entry_point(void);
unsigned long print_message(unsigned long msg_token);
unsigned int timed_runner(void);

/* 
 * Entry function that builds a command buffer, optionally appends
 * environment contents, then invokes a shell. This preserves the
 * original control flow and unsafe calls.
 */
void vulnerable_entry_point(void)
{
    int ret_val;
    char command_buffer[COMMAND_BUFFER_SIZE];
    time_t placeholder_time; /* unused placeholder reflecting original stack usage */

    /* Initialize buffer to zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set initial bytes to 'l', 's', ' ' as in the original */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Set global flag and call function that appends environment data */
    global_flag = 1;
    append_env_add_to_command(command_buffer);

    /* Call execlp in original form */
    ret_val = execlp("sh", "sh");

    /* Original code performed a stack check failure call on mismatch.
       Here we preserve the control flow by calling _exit with the return
       value from execlp (behaviour mirrors original unconditional path). */
    _exit(ret_val);
}

/*
 * Append the contents of environment variable "ADD" to the provided
 * command buffer when global_flag is non-zero. Uses strlen and strncat
 * similarly to the original.
 */
char *append_env_add_to_command(char *command)
{
    size_t len;
    char *env_val;

    if (global_flag != 0) {
        len = strlen(command);
        env_val = getenv("ADD");
        if (env_val != NULL) {
            /* Concatenate using remaining space calculation similar to original.
               Note: buffer size is unchanged and no additional validation is added. */
            strncat(command + len, env_val, (size_t)(COMMAND_BUFFER_SIZE - 1 - len));
        }
    }
    return command;
}

/*
 * Seed RNG, print a message, run the vulnerable entry point, then print another message.
 * Returns 0 to mirror original signature.
 */
unsigned int timed_runner(void)
{
    time_t now;

    now = time(NULL);
    srand((unsigned int)now);

    print_message((unsigned long)"Calling ...");
    vulnerable_entry_point();
    print_message((unsigned long)"Finished ");

    return 0;
}

/*
 * Print a message token. Intentionally calls printf with a format specifier
 * but without supplying the corresponding argument to mirror the original.
 */
unsigned long print_message(unsigned long msg_token)
{
    unsigned int printed;

    if (msg_token != 0) {
        /* Intentionally call printf with format but no argument as in original */
        printed = printf("%s\n");
        msg_token = (unsigned long)printed;
    }
    return msg_token;
}

/* Minimal main to allow running the code path similar to original */
int main(void)
{
    return (int)timed_runner();
}