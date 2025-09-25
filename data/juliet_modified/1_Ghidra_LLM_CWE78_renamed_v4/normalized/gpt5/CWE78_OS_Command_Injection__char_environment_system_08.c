#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Minimal declarations for stack protector handling (kept as in original flow) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Constants for readability */
#define COMMAND_BUFFER_SIZE 100

/* Forward declarations */
void vulnerable_network_handler(void);
int entry_point(void);
int always_true_check(void);
unsigned long print_message(unsigned long msg);

/* 
 * vulnerable_network_handler
 * - Prepares a command buffer, optionally appends an environment variable, and calls system().
 * - Buffer sizes and calls are intentionally left as in original logic.
 */
void vulnerable_network_handler(void)
{
    int check_result;
    size_t current_length;
    char *env_value;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long local_canary;

    /* capture stack guard value (preserve original anti-tamper flow) */
    local_canary = __stack_chk_guard;

    /* initialize buffer and set initial literal content */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    /* call out to the check that determines whether to use environment data */
    check_result = always_true_check();
    if (check_result != 0) {
        current_length = strlen(command_buffer);
        env_value = getenv("ADD");
        if (env_value != NULL) {
            /*
             * Append environment content into command_buffer without additional validation.
             * This preserves original behavior (possible overflow/command injection).
             */
            strncat(command_buffer + current_length, env_value,
                    (size_t)(COMMAND_BUFFER_SIZE - current_length));
        }
    }

    /* execute the assembled command */
    check_result = system(command_buffer);
    if (check_result == 0) {
        /* preserve original stack check and exit path */
        if (__stack_chk_guard == local_canary) {
            return;
        }
        __stack_chk_fail();
    }

    print_message((unsigned long)"command execution failed!");
    exit(1);
}

/* entry_point
 * - Seeds PRNG, prints messages, and invokes the vulnerable handler.
 */
int entry_point(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);

    print_message((unsigned long)"Calling ...");
    vulnerable_network_handler();
    print_message((unsigned long)"Finished ");

    return 0;
}

/* always_true_check
 * - Placeholder check that returns a constant value.
 */
int always_true_check(void)
{
    return 1;
}

/* print_message
 * - Prints a string if provided; returns the printed character count as a value.
 */
unsigned long print_message(unsigned long msg)
{
    unsigned int printed = 0;

    if (msg != 0) {
        printed = printf("%s\n", (char *)msg);
    }
    return (unsigned long)printed;
}

/* If compiled as a standalone program, map entry_point to main */
int main(void)
{
    return entry_point();
}