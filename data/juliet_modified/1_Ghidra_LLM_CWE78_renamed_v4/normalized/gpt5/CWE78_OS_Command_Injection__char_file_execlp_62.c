#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/* Constants for clarity */
#define COMMAND_BUFFER_SIZE 100

/* External source function (provided elsewhere) */
void badSource(char **data);

/* 
 * Function: vulnerable_network_handler
 * ------------------------------------
 * Prepares a command buffer, populates it via badSource, then invokes execlp.
 *
 * Note: This function intentionally preserves the original program behavior
 * (including its lack of input validation and direct call to execlp).
 */
void vulnerable_network_handler(void)
{
    int return_value;
    char *command_ptr;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Clear the buffer and set an initial command prefix "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    command_ptr = command_buffer;

    /* Populate command_ptr from an external source (e.g., file input) */
    badSource(&command_ptr);

    /* Invoke shell - original call preserved exactly (no additional args or checks) */
    return_value = execlp("sh", "sh");

    /* Return; no extra error handling added to preserve original behavior */
    (void)return_value;
}