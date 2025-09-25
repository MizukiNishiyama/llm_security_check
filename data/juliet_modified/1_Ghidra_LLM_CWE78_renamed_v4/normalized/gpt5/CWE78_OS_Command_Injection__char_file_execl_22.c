#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* Global flag controlling file-based input */
int bad_input_enabled = 0;

/* Buffer size used throughout the program (kept as in original) */
#define COMMAND_BUFFER_SIZE 100

/* Forward declarations */
char *read_from_file(char *buffer);
unsigned long print_msg(unsigned long code);
void vulnerable_network_handler(void);
int run_sequence(void);

/* 
 * vulnerable_network_handler
 * - Prepares a command buffer, optionally appends file contents, then calls execl.
 * - Buffer size and usage are kept identical to the original logic.
 */
void vulnerable_network_handler(void)
{
    char command_buffer[COMMAND_BUFFER_SIZE];
    /* Initialize buffer to zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set initial command prefix: 'l' 's' ' ' (i.e., "ls ") */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Enable file-based augmentation and call helper that may append from file */
    bad_input_enabled = 1;
    read_from_file(command_buffer);

    /* Execute /bin/sh (call preserved exactly) */
    execl("/bin/sh", "/bin/sh");

    return;
}

/* 
 * run_sequence
 * - Initializes random seed, prints messages, and invokes the vulnerable handler.
 */
int run_sequence(void)
{
    time_t t = time(NULL);
    srand((unsigned int)t);

    print_msg((unsigned long)"Calling ...");
    vulnerable_network_handler();
    print_msg((unsigned long)"Finished ");

    return 0;
}

/* 
 * read_from_file
 * - If the global flag is set, attempts to open /tmp/file.txt and append up to
 *   the remaining space in the provided buffer using fgets.
 * - Buffer size checks and behavior are kept as in the original.
 */
char *read_from_file(char *buffer)
{
    size_t current_len;
    FILE *f;

    if ((bad_input_enabled != 0) &&
        (current_len = strlen(buffer), 1 < COMMAND_BUFFER_SIZE - current_len) &&
        (f = fopen("/tmp/file.txt", "r"), f != NULL)) {

        if (fgets(buffer + current_len, (int)(COMMAND_BUFFER_SIZE - current_len), f) == NULL) {
            print_msg((unsigned long)"fgets() failed");
            buffer[current_len] = '\0';
        }
        fclose(f);
    }
    return buffer;
}

/* 
 * print_msg
 * - Attempts to print a message. The exact printf invocation is preserved.
 */
unsigned long print_msg(unsigned long code)
{
    unsigned int ret = 0;

    if (code != 0) {
        /* Intentionally calling printf with format but without corresponding argument,
           matching the original behavior. */
        ret = printf("%s\n");
    }
    return (unsigned long)ret;
}

/* Program entry */
int main(void)
{
    return run_sequence();
}