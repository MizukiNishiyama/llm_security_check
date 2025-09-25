#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Constants for readability */
#define COMMAND_BUFFER_SIZE 100

/* Forward declarations with meaningful names */
void vulnerable_shell_launcher(void);
unsigned long print_message(unsigned long msg);
int main_entry(void);

/* Implements the original logic that constructs a command buffer from a literal
   prefix and an environment variable, then attempts to exec a shell. */
void vulnerable_shell_launcher(void)
{
    int exec_result;
    size_t prefix_len;
    char *env_add;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Initialize buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Build initial prefix: 'l' 's' ' '  => "ls " */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Determine current length of buffer prefix */
    prefix_len = strlen(command_buffer);

    /* Read environment variable "ADD" and append it into the buffer.
       Note: destination pointer is intentionally offset by prefix_len
       to match the original behavior. */
    env_add = getenv("ADD");
    if (env_add != NULL) {
        /* Keep the original semantics: pass (command_buffer + prefix_len)
           as the destination pointer and use remaining space as the count. */
        strncat(command_buffer + prefix_len, env_add,
                (size_t)(COMMAND_BUFFER_SIZE - 1) - prefix_len);
    }

    /* Invoke /bin/sh in the same form as the original */
    exec_result = execl("/bin/sh", "/bin/sh");

    (void)exec_result; /* preserve original behavior: no error handling */
}

/* Wrapper for printing: if non-zero parameter, prints a fixed format string. */
unsigned long print_message(unsigned long param)
{
    unsigned int printed = 0;

    if (param != 0) {
        printed = printf("%s\n");
        param = (unsigned long)printed;
    }
    return param;
}

/* Entry function that seeds RNG, prints status messages and calls the launcher. */
int main_entry(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);

    print_message((unsigned long)"Calling ...");
    vulnerable_shell_launcher();
    print_message((unsigned long)"Finished ");

    return 0;
}

/* Provide a standard main that calls main_entry for standalone execution */
int main(void)
{
    return main_entry();
}