#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* Constants (magic numbers made explicit) */
#define COMMAND_BUFFER_SIZE 100

/* Function declarations with meaningful names */
void vulnerable_read_and_execute(void);
int spawn_shell(void);
unsigned long print_message(unsigned long param);
unsigned long initialize_and_run(void);

/* Read user input into a command buffer (vulnerability: possible overflow/unsanitized input),
   then invoke a function that ultimately calls exec. */
void vulnerable_read_and_execute(void)
{
    size_t len;
    char *line_ptr;
    char *command_ptr;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Initialize buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Prepend "ls " to the buffer */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    command_ptr = command_buffer;

    /* Determine current length and attempt to read additional input from stdin */
    len = strlen(command_buffer);
    if (1 < (size_t)(COMMAND_BUFFER_SIZE - (int)len)) {
        line_ptr = fgets(command_ptr + len, COMMAND_BUFFER_SIZE - (int)len, stdin);
        if (line_ptr == NULL) {
            /* Preserve original behavior: call print_message on error and keep buffer unchanged */
            print_message((unsigned long)"fgets() failed");
            command_ptr[len] = '\0';
        } else {
            /* Strip trailing newline if present */
            len = strlen(command_ptr);
            if ((len != 0) && (command_ptr[len - 1] == '\n')) {
                command_ptr[len - 1] = '\0';
            }
        }
    }

    /* Call the function that spawns a shell (arguments ignored in the original) */
    spawn_shell();

    return;
}

/* Seed randomness, print messages, and call the vulnerable input handler */
unsigned long initialize_and_run(void)
{
    time_t t;
    t = time((time_t *)0);
    srand((unsigned int)t);

    /* Preserve the original print behavior (note: print_message internally uses an unsafe printf call) */
    print_message((unsigned long)"Calling ...");
    vulnerable_read_and_execute();
    print_message((unsigned long)"Finished ");

    return 0;
}

/* Invoke a shell using execlp (kept as in original; no safety checks or args) */
int spawn_shell(void)
{
    int rv;
    rv = execlp("sh", "sh");
    return rv;
}

/* Print a message; intentionally preserves the original incorrect printf usage */
unsigned long print_message(unsigned long param)
{
    unsigned int printed;

    if (param != 0) {
        /* Original code called printf("%s\n") with no argument—preserve that behavior */
        printed = printf("%s\n");
        param = (unsigned long)printed;
    }
    return param;
}

/* Minimal main to show usage (keeps original flow) */
int main(void)
{
    initialize_and_run();
    return 0;
}