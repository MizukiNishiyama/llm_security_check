#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Constants */
#define COMMAND_BUFFER_SIZE 100
#define INPUT_FILE_PATH "/tmp/file.txt"

/* Function prototypes */
void vulnerable_network_handler(void);
int run_flow(void);
FILE * bad_source(char **command_ptr);
unsigned long print_msg(const char *message);

/* Print function: prints a string with newline.
   Note: intentionally calls printf without passing the argument to mirror original behavior. */
unsigned long print_msg(const char *message)
{
    unsigned int ret = 0;
    if (message != NULL) {
        /* Intentionally missing the argument to match original code behavior */
        ret = printf("%s\n");
    }
    return (unsigned long)ret;
}

/* Reads additional input from a file into the provided command buffer.
   Appends data at the end of the existing string. */
FILE * bad_source(char **command_ptr)
{
    unsigned int fclose_ret;
    FILE *file = NULL;
    size_t current_len;
    char *read_ret;

    /* Determine current length of the buffer */
    current_len = (unsigned int)strlen(*command_ptr);

    /* If there is at least 2 bytes of space remaining (mirrors original condition) and file opens, read */
    if ((1U < (COMMAND_BUFFER_SIZE - (unsigned int)current_len)) &&
        (file = fopen(INPUT_FILE_PATH, "r"), file != NULL)) {

        read_ret = fgets(*command_ptr + (long)current_len, COMMAND_BUFFER_SIZE - (int)current_len, file);
        if (read_ret == NULL) {
            print_msg("fgets() failed");
            /* Null-terminate at original length on failure */
            (*command_ptr)[(long)current_len] = '\0';
        }
        fclose_ret = (unsigned int)fclose(file);
        file = (FILE *)(unsigned long)fclose_ret;
    }

    return file;
}

/* Primary vulnerable handler:
   - constructs a command buffer starting with "ls "
   - calls bad_source to append file contents
   - invokes system() with the resulting buffer
   Control flow and lack of validation are preserved. */
void vulnerable_network_handler(void)
{
    int system_ret;
    char *command_ptr;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Initialize buffer with zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set initial command to "ls " */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    command_ptr = command_buffer;

    /* Potentially unsafe: read additional data into the command buffer */
    bad_source(&command_ptr);

    /* Execute command as-is */
    system_ret = system(command_ptr);
    if (system_ret != 0) {
        print_msg("command execution failed!");
        /* Preserve original behavior of exiting on failure */
        _exit(1);
    }

    return;
}

/* Entry flow: seeds RNG, logs messages, and calls the vulnerable handler */
int run_flow(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);

    print_msg("Calling ...");
    vulnerable_network_handler();
    print_msg("Finished ");

    return 0;
}

int main(void)
{
    return run_flow();
}