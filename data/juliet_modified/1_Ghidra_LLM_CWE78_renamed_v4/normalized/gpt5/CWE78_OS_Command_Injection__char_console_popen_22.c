#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* External globals and helpers (kept as in original binary) */
extern int _CWE78_OS_Command_Injection__char_console_popen_22_badGlobal;
char *func_2(char *cmd_buffer); /* external helper returning command string */

/* Stack protector symbols (kept to mirror original stack check behavior) */
extern uintptr_t __stack_chk_guard;
void __stack_chk_fail(void);

/* Constants */
#define COMMAND_BUFFER_SIZE 100
#define POPEN_MODE "w"

/* Function: vulnerable_command_executor
 * Purpose: Prepare a command buffer, call an external function to finalize it,
 *          and execute it via popen/pclose. The original control flow and
 *          dangerous calls are preserved.
 */
void vulnerable_command_executor(void)
{
    uintptr_t local_guard;
    char command_buffer[COMMAND_BUFFER_SIZE];
    char *command_str;
    FILE *pipe;
    unsigned int close_result;

    /* Preserve stack guard value for checking later (mirrors original behavior) */
    local_guard = __stack_chk_guard;

    /* Initialize the command buffer to zeros and set the first bytes to "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Set the global control flag as in the original binary */
    _CWE78_OS_Command_Injection__char_console_popen_22_badGlobal = 1;

    /* Call external helper to obtain the final command string (pointer may be same buffer) */
    command_str = func_2(command_buffer);

    /* Execute the command using popen and immediately close it with pclose */
    pipe = popen(command_str, POPEN_MODE);
    if (pipe != NULL) {
        close_result = pclose(pipe);
        /* preserve the original cast behavior */
        pipe = (FILE *)(uintptr_t)close_result;
    }

    /* Stack check: compare guard value and call failure handler on mismatch */
    if (__stack_chk_guard != local_guard) {
        __stack_chk_fail();
    }

    return;
}