#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* Minimal global canary to reproduce original stack check behavior */
static long GLOBAL_STACK_GUARD = 0xdeadbeef;

/* Constants for buffer sizes and defaults */
#define COMMAND_BUFFER_SIZE 100

/* Function prototypes with clearer names */
void vulnerable_network_handler(void);
unsigned int seed_and_execute(void);
char * build_command_from_file(char *command_buffer);
unsigned long print_message(unsigned long param);

/* Entry equivalent to the original func_0 */
void vulnerable_network_handler(void)
{
    int result;
    char *cmd_ptr;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long local_canary;

    /* replicate stack guard load and check */
    local_canary = GLOBAL_STACK_GUARD;

    /* zero the command buffer then set initial bytes to "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 0x6c; /* 'l' */
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */

    /* attempt to append data from file into the command buffer */
    cmd_ptr = build_command_from_file(command_buffer);

    /* execute the constructed command using system() */
    result = system(cmd_ptr);

    /* preserve original control flow on non-zero return */
    if (result != 0) {
        print_message((unsigned long)"command execution failed!");
        exit(1);
    }

    /* stack canary check as in original */
    if (GLOBAL_STACK_GUARD != local_canary) {
        /* in original code this calls __stack_chk_fail(); reproduce behavior by aborting */
        abort();
    }

    return;
}

/* Equivalent to func_1: seeds RNG, prints messages, and invokes handler */
unsigned int seed_and_execute(void)
{
    time_t t;

    t = time((time_t *)0x0);
    srand((unsigned int)t);

    print_message((unsigned long)"Calling ...");
    vulnerable_network_handler();
    print_message((unsigned long)"Finished ");

    return 0;
}

/* Equivalent to func_2: appends data from /tmp/file.txt into provided buffer */
char * build_command_from_file(char *command_buffer)
{
    size_t current_len;
    FILE *fp;
    char *res;

    current_len = strlen(command_buffer);

    /* if there is space, attempt to read from the file and append into buffer */
    if ((1 < (COMMAND_BUFFER_SIZE - current_len)) &&
        (fp = fopen("/tmp/file.txt", "r"), fp != (FILE *)0x0)) {

        res = fgets(command_buffer + current_len,
                    COMMAND_BUFFER_SIZE - (int)current_len,
                    fp);

        if (res == (char *)0x0) {
            print_message((unsigned long)"fgets() failed");
            /* restore string terminator as in original */
            command_buffer[current_len] = '\0';
        }

        fclose(fp);
    }

    return command_buffer;
}

/* Equivalent to func_3: prints a message when param is non-zero */
unsigned long print_message(unsigned long param)
{
    unsigned int printed = 0;

    if (param != 0) {
        /* preserve original call shape: printf invoked with format only */
        printed = printf("%s\n");
        param = (unsigned long)printed;
    }

    return param;
}

/* optional main to allow running the flow (kept minimal) */
int main(void)
{
    return (int)seed_and_execute();
}