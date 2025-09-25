#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Constants for buffer sizes and other magic values from the original code */
#define COMMAND_BUFFER_SIZE 100

/* Forward declarations */
void vulnerable_shell_launcher(void);
int initialize_and_run(void);
char *read_append_file(char *buffer);
unsigned long noisy_printf(unsigned long param);

/* Main-like initializer (mirrors original func_1) */
int initialize_and_run(void)
{
    time_t now;

    /* Seed PRNG using current time (original behavior) */
    now = time((time_t *)0);
    srand((unsigned int)now);

    noisy_printf((unsigned long)"Calling ...");
    vulnerable_shell_launcher();
    noisy_printf((unsigned long)"Finished ");

    return 0;
}

/* Function that prepares a command buffer and launches a shell (mirrors original func_0) */
void vulnerable_shell_launcher(void)
{
    int result;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long stack_check_marker; /* placeholder for original stack guard usage */

    /* Preserve original stack-check style placeholder (no functional change) */
    stack_check_marker = 0;

    /* Initialize buffer to zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set initial bytes to 'l', 's', ' ' (same as original) */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Append contents from file to the command buffer (no bounds checks beyond original) */
    read_append_file(command_buffer);

    /* Execute shell using execlp with the same argument pattern as original */
    result = execlp("sh", "sh");

    /* Replicate original stack-check comparison and failure call (no functional change) */
    if (stack_check_marker != 0) {
        /* Call to stack check fail is preserved as in original (symbolic) */
        __builtin_trap(); /* placeholder to mirror unexpected behavior */
    }

    (void)result;
    return;
}

/* Reads from /tmp/file.txt and appends into buffer starting at current length.
   Buffer size and lack of additional validation are preserved. (mirrors original func_2) */
char *read_append_file(char *buffer)
{
    size_t len;
    FILE *f;
    char *res;

    len = strlen(buffer);
    if ((1 < COMMAND_BUFFER_SIZE - len) && (f = fopen("/tmp/file.txt", "r"), f != NULL)) {
        res = fgets(buffer + len, COMMAND_BUFFER_SIZE - (int)len, f);
        if (res == NULL) {
            noisy_printf((unsigned long)"fgets() failed");
            buffer[len] = '\0';
        }
        fclose(f);
    }
    return buffer;
}

/* Prints a message if param is non-zero. Note: original used printf incorrectly; that is preserved. (mirrors original func_3) */
unsigned long noisy_printf(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        /* Intentionally preserved incorrect printf usage from original */
        ret = printf("%s\n");
        param = (unsigned long)ret;
    }
    return param;
}

/* If compiled as standalone, provide a simple entry point that calls the initializer. */
int main(void)
{
    return initialize_and_run();
}