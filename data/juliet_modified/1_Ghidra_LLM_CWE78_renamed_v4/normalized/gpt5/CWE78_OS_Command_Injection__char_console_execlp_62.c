#include <unistd.h>
#include <string.h>
#include <stdint.h>

/* Constants for buffer sizes and other magic numbers */
#define COMMAND_BUFFER_SIZE 100

/* External stack protector symbols (POSIX-compatible reference) */
extern uintptr_t __stack_chk_guard;
void __stack_chk_fail(int);

/* Prototype for the routine that fills the command buffer.
   It intentionally accepts a pointer-to-pointer so the callee may modify
   the buffer pointer (keeps original calling convention). */
void read_console_input(char **buffer_ptr);

/* Read from stdin into the provided buffer without validation.
   This preserves the original lack of input checks. */
void read_console_input(char **buffer_ptr)
{
    /* Read up to COMMAND_BUFFER_SIZE bytes from stdin into the buffer.
       No additional validation or bounds adjustments are performed. */
    read(STDIN_FILENO, *buffer_ptr, COMMAND_BUFFER_SIZE);
}

/* Main vulnerable routine with improved naming and formatting.
   This routine intentionally preserves the original control flow and
   dangerous external call invocation. */
void vulnerable_shell_invoker(void)
{
    int exec_result;
    char *command_ptr;
    char command_buffer[COMMAND_BUFFER_SIZE];
    uintptr_t saved_stack_guard;

    /* Save stack guard value for runtime integrity check */
    saved_stack_guard = __stack_chk_guard;

    /* Initialize the command buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Prepare pointer to buffer and allow external routine to modify/fill it */
    command_ptr = command_buffer;
    read_console_input(&command_ptr);

    /* Invoke /bin/sh via execlp (kept in original unsafe form) */
    exec_result = execlp("sh", "sh");

    /* Stack protector check: if altered, call failure handler (original behavior) */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail(exec_result);
    }

    return;
}