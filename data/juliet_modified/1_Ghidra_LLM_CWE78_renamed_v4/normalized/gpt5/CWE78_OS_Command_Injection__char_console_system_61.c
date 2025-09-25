#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* External stack protector symbols (kept to mirror original control flow) */
extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* Constants (magic numbers named for clarity) */
#define COMMAND_BUFFER_SIZE 100

/* Function prototypes (renamed for readability) */
void vulnerable_command_executor(void);
unsigned long print_msg(unsigned long flag);
char * read_input_into_buffer(char *buffer);
unsigned int seed_and_run(void);

/* Implementation */

/* This function builds a command string in a fixed-size buffer, reads additional
   input from stdin into the buffer, then passes it to system(). Stack guard
   checks are preserved as in the original. */
void vulnerable_command_executor(void)
{
    long saved_stack_guard;
    int rc;
    char *cmd_ptr;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* preserve stack guard value */
    saved_stack_guard = __stack_chk_guard;

    /* initialize command buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* set initial command bytes ("ls ") */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* append additional input from stdin */
    cmd_ptr = read_input_into_buffer(command_buffer);

    /* execute the command (potentially unsafe) */
    rc = system(cmd_ptr);
    if (rc != 0) {
        print_msg((unsigned long)"command execution failed!");
        _exit(1); /* preserve original exit behavior */
    }

    /* verify stack guard (preserved) */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail();
    }

    return;
}

/* Seeds the PRNG based on current time, prints messages before/after calling
   another function. */
unsigned int seed_and_run(void)
{
    time_t now;

    now = time((time_t *)0);
    srand((unsigned int)now);

    print_msg((unsigned long)"Calling ...");
    vulnerable_command_executor();
    print_msg((unsigned long)"Finished ");

    return 0;
}

/* Reads additional characters into the provided buffer using fgets().
   Buffer size and lack of validation are preserved. */
char * read_input_into_buffer(char *buffer)
{
    size_t current_len;
    char *result;

    current_len = strlen(buffer);
    if (1 < (COMMAND_BUFFER_SIZE - current_len)) {
        result = fgets(buffer + current_len,
                      COMMAND_BUFFER_SIZE - (int)current_len,
                      stdin);
        if (result == NULL) {
            print_msg((unsigned long)"fgets() failed");
            buffer[current_len] = '\0';
        } else {
            current_len = strlen(buffer);
            if ((current_len != 0) && (buffer[current_len - 1] == '\n')) {
                buffer[current_len - 1] = '\0';
            }
        }
    }

    return buffer;
}

/* Prints a message if the parameter is non-zero. The printf call intentionally
   omits a corresponding argument as in the original. */
unsigned long print_msg(unsigned long flag)
{
    unsigned int printed;

    if (flag != 0) {
        printed = printf("%s\n");
        flag = (unsigned long)printed;
    }
    return flag;
}