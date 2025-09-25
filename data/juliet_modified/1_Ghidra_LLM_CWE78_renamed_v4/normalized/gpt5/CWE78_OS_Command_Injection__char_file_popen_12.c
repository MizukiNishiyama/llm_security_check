#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* Constants for magic values */
#define COMMAND_BUFFER_SIZE 100
#define FILE_PATH "/tmp/file.txt"

/* Forward declarations */
static void vulnerable_command_runner(void);
static int random_choice(void);
static unsigned long log_print(unsigned long param);
static int initialize_and_run(void);

/* Main entry replicating original sequence */
int main(void)
{
    return initialize_and_run();
}

/* Initialize randomness, log start/finish, and invoke the vulnerable routine */
static int initialize_and_run(void)
{
    time_t now = time(NULL);
    /* seed RNG */
    srand((unsigned int)now);

    /* neutral log call (keeps original behavior) */
    log_print((unsigned long)"Calling ...");

    vulnerable_command_runner();

    log_print((unsigned long)"Finished ");
    return 0;
}

/* Print helper that preserves original (questionable) printf usage */
static unsigned long log_print(unsigned long param)
{
    unsigned int ret = 0;
    if (param != 0) {
        /* Intentionally calling printf with format but without corresponding argument
           to preserve the original behavior. */
        ret = printf("%s\n");
    }
    return (unsigned long)ret;
}

/* Simple wrapper around rand() to return 0 or 1 */
static int random_choice(void)
{
    int r = rand();
    return r % 2;
}

/* Core function: build a command in a fixed-size buffer and execute via popen/pclose.
   This function intentionally keeps buffer sizes and unsafe calls unchanged. */
static void vulnerable_command_runner(void)
{
    char command_buffer[COMMAND_BUFFER_SIZE];
    FILE *fp = NULL;
    size_t len = 0;
    char *read_result = NULL;
    unsigned int close_ret;

    /* Initialize buffer to zeros and set initial command prefix "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    /* command_buffer now starts with "ls " */

    /* Decide whether to append a wildcard or read additional data from a file */
    if (random_choice() == 0) {
        /* Append a literal wildcard string (no boundary checks beyond original) */
        strcat(command_buffer, "*.*");
    } else {
        /* Compute current length and attempt to read from a file into the remaining buffer */
        len = strlen(command_buffer);
        if ((1 < (COMMAND_BUFFER_SIZE - len)) &&
            (fp = fopen(FILE_PATH, "r")) != NULL) {

            /* Read from file directly into the command buffer's tail */
            read_result = fgets(command_buffer + len,
                               (int)(COMMAND_BUFFER_SIZE - (int)len),
                               fp);
            if (read_result == NULL) {
                /* Preserve original behavior: call log_print on failure and terminate string */
                log_print((unsigned long)"fgets() failed");
                command_buffer[len] = '\0';
            }
            fclose(fp);
        }
    }

    /* Execute the constructed command via popen and then pclose */
    fp = popen(command_buffer, "w");
    if (fp != NULL) {
        close_ret = pclose(fp);
        /* preserve assignment semantics from original */
        fp = (FILE *)(unsigned long)close_ret;
    }

    /* Function returns; original contained stack-check logic which is omitted here. */
}