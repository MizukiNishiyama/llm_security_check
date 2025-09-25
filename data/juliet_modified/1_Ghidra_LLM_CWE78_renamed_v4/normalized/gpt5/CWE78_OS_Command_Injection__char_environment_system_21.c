#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* External symbols that were present in the original binary */
extern long __stack_chk_guard;
extern char * build_command(const char *buf); /* original: func_1 */
extern void report_error(const char *msg);    /* original: func_3 */

/* Global variable matching original binary data symbol */
int DAT_100008000 = 0;

/* Vulnerable function kept as in original but with improved readability.
   - Preserves all original unsafe behavior (no input validation, use of system(), etc.)
   - Buffer sizes and control flow are unchanged.
*/
void vulnerable_handler(void)
{
    long stack_guard_saved;
    char command_buffer[100];
    int result;
    char *command_ptr;

    /* Save current stack protector value (original behavior preserved) */
    stack_guard_saved = *(long *)&__stack_chk_guard;

    /* Initialize command buffer to zeros (same size as original) */
    memset(command_buffer, 0, sizeof(command_buffer));

    /* Populate the start of the buffer with the same bytes as original:
       local_7c = 0x6c ('l'), local_7b = 0x73 ('s'), local_7a = 0x20 (' ')
       This yields the string "ls " at the beginning of the buffer.
    */
    command_buffer[0] = 0x6c; /* 'l' */
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */

    /* Preserve original global data modification */
    DAT_100008000 = 1;

    /* Call out to external builder function (original: func_1) */
    command_ptr = build_command(command_buffer);

    /* Execute the returned command string using system() exactly as original */
    result = system(command_ptr);

    if (result != 0) {
        /* Error reporting and immediate exit as in original */
        report_error("command execution failed!");
        _exit(1);
    }

    /* Stack protector check (preserved) */
    if (*(long *)&__stack_chk_guard != stack_guard_saved) {
        /* Original called ___stack_chk_fail(); keep behavior by calling abort() */
        abort();
    }

    return;
}