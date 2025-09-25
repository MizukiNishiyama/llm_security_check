#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Constants and globals */
#define COMMAND_BUFFER_SIZE 100

/* External symbols (kept as in original layout) */
extern long __stack_chk_guard;

/* Control-flow/global flag preserved from original code */
int CWE78_OS_Command_Injection__char_environment_system_22_badGlobal = 0;

/* Forward declarations for external helper functions (kept as original signatures) */
char * build_command_from_buffer(char *buffer);
void report_error(const char *msg);
void __stack_chk_fail(void);

/* Renamed function preserving original vulnerable behavior and flow */
void vulnerable_command_injection_handler(void)
{
    long saved_stack_guard;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Preserve original stack guard check behavior */
    saved_stack_guard = __stack_chk_guard;

    /* Initialize buffer to zeros (same size as original) */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Populate the beginning of the buffer with literal bytes (same as original) */
    command_buffer[0] = 'l'; /* 0x6c */
    command_buffer[1] = 's'; /* 0x73 */
    command_buffer[2] = ' '; /* 0x20 */

    /* Set the global flag as in original code */
    CWE78_OS_Command_Injection__char_environment_system_22_badGlobal = 1;

    /*
     * Call out to an external function that builds/returns the command string.
     * The returned pointer is passed directly to system() without validation,
     * preserving the original unsafe behavior.
     */
    char *command_to_execute = build_command_from_buffer(command_buffer);
    int system_result = system(command_to_execute);

    /* Preserve original check/behavior on non-zero return */
    if (system_result != 0) {
        report_error("command execution failed!");
        _exit(1); /* preserved original termination call */
    }

    /* Preserve original stack guard verification */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail();
    }

    return;
}

/* Stubs to allow compilation; real implementations expected from original binary */
char * build_command_from_buffer(char *buffer)
{
    /* Placeholder: original function provided by binary; left unchanged in behavior assumption */
    return buffer;
}

void report_error(const char *msg)
{
    /* Placeholder for original error reporting function */
    fprintf(stderr, "%s\n", msg);
}

void __stack_chk_fail(void)
{
    /* Placeholder mimic of stack check failure handler */
    _exit(1);
}