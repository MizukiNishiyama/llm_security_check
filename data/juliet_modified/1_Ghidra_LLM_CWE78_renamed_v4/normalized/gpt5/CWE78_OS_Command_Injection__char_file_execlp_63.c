#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 100

/* Neutral comments describe purpose of blocks without altering behavior */

/* Forward declarations */
void vulnerable_file_loader(void);
int execute_shell(void);
unsigned long print_message(unsigned long msg);

/* Entry-like function: seeds RNG, prints messages, and calls the vulnerable loader */
int start_sequence(void)
{
    time_t now;

    /* seed the pseudo-random generator */
    now = time((time_t *)0);
    srand((unsigned int)now);

    print_message((unsigned long)"Calling ...");
    vulnerable_file_loader();
    print_message((unsigned long)"Finished ");

    return 0;
}

/* Loads data from a temporary file into a fixed-size buffer and calls execute_shell */
void vulnerable_file_loader(void)
{
    size_t current_len;
    FILE *file;
    char *read_ptr;
    char buffer[BUFFER_SIZE];
    char *buffer_ptr;

    /* Initialize buffer to zeros */
    memset(buffer, 0, BUFFER_SIZE);

    /* Prepend literal "ls " to the buffer */
    buffer[0] = 'l';
    buffer[1] = 's';
    buffer[2] = ' ';
    buffer_ptr = buffer;

    /* Determine current length of the buffer */
    current_len = strlen(buffer);

    /* Attempt to open /tmp/file.txt and read remaining bytes into the buffer.
       No additional validation or bounds checks beyond using fgets with remaining size. */
    if ((1 < (int)(BUFFER_SIZE - current_len)) && (file = fopen("/tmp/file.txt", "r"), file != NULL)) {
        read_ptr = fgets(buffer_ptr + current_len, (int)(BUFFER_SIZE - current_len), file);
        if (read_ptr == NULL) {
            /* Preserve original behavior: call print_message on error and terminate the read region */
            print_message((unsigned long)"fgets() failed");
            buffer_ptr[current_len] = '\0';
        }
        fclose(file);
    }

    /* Pass address of buffer to the next stage (function expects a pointer but does not use it safely) */
    execute_shell();

    return;
}

/* Executes a shell using execlp; returns the result of execlp */
int execute_shell(void)
{
    int ret;
    /* Direct invocation of execlp with arguments as in original code */
    ret = execlp("sh", "sh");
    return ret;
}

/* Prints a message using printf and returns the numeric result.
   Note: the original call to printf supplies a format string without matching arguments. */
unsigned long print_message(unsigned long msg)
{
    unsigned int printed;

    if (msg != 0) {
        printed = printf("%s\n");
        msg = (unsigned long)printed;
    }
    return msg;
}

/* If compiled as a standalone program, provide a minimal main that invokes start_sequence */
#ifdef BUILD_STANDALONE
int main(void)
{
    return start_sequence();
}
#endif