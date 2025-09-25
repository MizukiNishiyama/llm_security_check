#include <string.h>
#include <unistd.h>

/* External functions/variables expected to be provided elsewhere.
   These are declared to preserve the original control flow and
   stack-protection checks present in the input. */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Prototype for an external helper that fills a buffer pointer.
   The implementation is intentionally not provided here to keep the
   original vulnerability surface and behavior. */
void fill_buffer_from_source(char **buffer_ptr);

/* Constants derived from magic numbers in the original binary */
#define COMMAND_BUFFER_SIZE 100

/* Function: vulnerable_command_executor
   - Rewritten for readability: preserves original logic and vulnerabilities.
   - Allocates a fixed-size command buffer, sets initial bytes,
     calls an external filler function, then invokes execl().
   - No input validation, bounds checks, or safety fixes are added. */
void vulnerable_command_executor(void)
{
    long stack_guard_snapshot;
    char command_buffer[COMMAND_BUFFER_SIZE];
    char *command_ptr;

    /* Capture stack guard value for later integrity check */
    stack_guard_snapshot = __stack_chk_guard;

    /* Initialize the command buffer with zeros (same size as original) */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set first three bytes to specific values (preserves original data) */
    command_buffer[0] = 0x6c; /* 'l' */
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */

    /* Prepare pointer to buffer and pass to external filler function */
    command_ptr = command_buffer;
    fill_buffer_from_source(&command_ptr);

    /* Execute shell; call kept identical to original (vulnerable behavior preserved) */
    execl("/bin/sh", "/bin/sh");

    /* Stack guard check preserved exactly as in original control flow */
    if (__stack_chk_guard != stack_guard_snapshot) {
        __stack_chk_fail(0);
    }

    return;
}