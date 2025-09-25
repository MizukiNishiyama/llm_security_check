#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* External helper functions (implementation assumed elsewhere) */
void append_console_input(char **command_ptr); /* reads additional input into command buffer */
void report_failure(const char *message);      /* reports an error message */

/* Constant definitions for magic values */
#define COMMAND_BUFFER_SIZE 100

/* Purpose: prepares a command buffer, allows external input to modify it,
   then executes the assembled command using system(). The buffer size and
   lack of input validation are preserved as in the original. */
void vulnerable_command_executor(void)
{
    int result;
    char *command_ptr;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Initialize buffer to zeros and set initial command "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    command_ptr = command_buffer;

    /* External function is expected to modify command_ptr (e.g., append console input) */
    append_console_input(&command_ptr);

    /* Execute the assembled command (unsafe call preserved) */
    result = system(command_ptr);

    /* Preserve original control flow on non-zero return */
    if (result != 0) {
        report_failure("command execution failed!");
        _exit(1);
    }

    return;
}