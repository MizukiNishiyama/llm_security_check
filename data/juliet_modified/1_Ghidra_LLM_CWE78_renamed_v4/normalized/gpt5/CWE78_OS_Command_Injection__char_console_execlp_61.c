#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* Constants for buffer sizes and defaults */
#define COMMAND_BUFFER_SIZE 100

/* Forward declarations */
void vulnerable_network_handler(void);
char *read_append_input(char *buffer);
unsigned long log_message(unsigned long tag);

/* Entry point replicating original control flow */
int main(void)
{
    time_t now;

    /* seed RNG with current time (no additional checks) */
    now = time((time_t *)0);
    srand((unsigned int)now);

    /* Informational prints (preserve original printing behavior) */
    log_message((unsigned long)"Calling ...");

    /* Call the vulnerable handler that preserves original insecure behavior */
    vulnerable_network_handler();

    log_message((unsigned long)"Finished ");

    return 0;
}

/* Handler that prepares a command buffer and launches a shell */
void vulnerable_network_handler(void)
{
    int result;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long stack_cookie;

    /* Stack protector snapshot (kept as a local marker, original behavior preserved) */
    stack_cookie = 0; /* placeholder to mirror original stack check usage */

    /* Initialize buffer to zeros, then set a small prefix "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Append input from stdin into the command buffer (no bounds validation beyond original logic) */
    read_append_input(command_buffer);

    /* Execute a shell; original used execlp("sh","sh") and that is preserved */
    result = execlp("sh", "sh");

    /* Original had a stack check call on mismatch; we keep similar flow without adding checks */
    (void)result;
}

/* Append input from stdin into buffer starting at current length.
   Preserves original fgets-based behavior and trimming of trailing newline. */
char *read_append_input(char *buffer)
{
    size_t current_len;
    char *fres;

    current_len = strlen(buffer);
    if (1 < (size_t)(COMMAND_BUFFER_SIZE - (int)current_len)) {
        fres = fgets(buffer + current_len, COMMAND_BUFFER_SIZE - (int)current_len, stdin);
        if (fres == NULL) {
            /* Preserve original behavior: call log_message and set terminator */
            log_message((unsigned long)"fgets() failed");
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

/* Logging helper that calls printf with the same signature/behavior as original.
   Note: intentionally mirrors the original call pattern. */
unsigned long log_message(unsigned long tag)
{
    unsigned int ret;

    if (tag != 0) {
        /* Intentionally call printf with the same format as the original code */
        ret = printf("%s\n");
        tag = (unsigned long)ret;
    }
    return tag;
}