#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* Constants (magic numbers replaced) */
#define COMMAND_BUFFER_SIZE 100
#define FILEPATH "/tmp/file.txt"

/* Globals matching original binary symbols (kept as-is to preserve control flow) */
int GLOBAL_FLAG = 1;
long GLOBAL_STACK_GUARD = 0xdeadbeef;

/* Prototype for external stack-check fail (kept as in original) */
void __stack_chk_fail(void *);

/* Forward declarations with meaningful names */
void vulnerable_execute_from_file(void);
int entry_point(void);
unsigned long print_message(unsigned long param);

/* Implementation */

/* 
 * Function: vulnerable_execute_from_file
 * -------------------------------------
 * Builds a command buffer starting with "ls " and appends data read from FILEPATH if GLOBAL_FLAG is set.
 * Then opens a popen stream with that command. Buffer sizes and checks mirror the original behavior.
 */
void vulnerable_execute_from_file(void)
{
    unsigned int close_result;
    size_t current_len;
    FILE *file_stream;
    char *fgets_result;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long local_guard;

    /* Preserve stack guard behavior similar to original */
    local_guard = GLOBAL_STACK_GUARD;

    /* Initialize buffer and set initial command "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* If global flag is set and there is room in the buffer, try to read additional text from file */
    if ((GLOBAL_FLAG != 0) && ((current_len = strlen(command_buffer)), 1 < COMMAND_BUFFER_SIZE - current_len)) {
        file_stream = fopen(FILEPATH, "r");
        if (file_stream != NULL) {
            fgets_result = fgets(command_buffer + current_len, (int)(COMMAND_BUFFER_SIZE - current_len), file_stream);
            if (fgets_result == NULL) {
                /* Mirror original behavior: call print_message and restore termination */
                print_message((unsigned long)"fgets() failed");
                command_buffer[current_len] = '\0';
            }
            fclose(file_stream);
        }
    }

    /* Execute the constructed command using popen/pclose (dangerous API preserved) */
    file_stream = popen(command_buffer, "w");
    if (file_stream != NULL) {
        close_result = pclose(file_stream);
        file_stream = (FILE *)(uintptr_t)close_result;
    }

    /* Stack guard check as in original flow */
    if (GLOBAL_STACK_GUARD == local_guard) {
        return;
    }

    __stack_chk_fail(file_stream);
}

/*
 * Function: entry_point
 * ---------------------
 * Seeds PRNG using current time, prints messages around calling the vulnerable function.
 */
int entry_point(void)
{
    time_t t;
    t = time(NULL);
    srand((unsigned int)t);
    print_message((unsigned long)"Calling ...");
    vulnerable_execute_from_file();
    print_message((unsigned long)"Finished ");
    return 0;
}

/*
 * Function: print_message
 * -----------------------
 * Prints a message when param is non-zero. Mimics original faulty printf usage.
 */
unsigned long print_message(unsigned long param)
{
    unsigned int printed;
    if (param != 0) {
        /* Intentionally uses printf with format specifier but no argument to mirror original behavior */
        printed = printf("%s\n");
        param = (unsigned long)printed;
    }
    return param;
}