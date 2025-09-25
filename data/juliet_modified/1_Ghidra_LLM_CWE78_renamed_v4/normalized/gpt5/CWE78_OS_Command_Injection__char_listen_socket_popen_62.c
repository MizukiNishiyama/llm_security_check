#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* External stack protector symbols (preserve original stack check logic) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void *);

/* Constants mirroring magic values from original code */
#define COMMAND_BUFFER_SIZE 100

/* Forward declaration of helper that fills the command buffer.
   The implementation is assumed to be provided elsewhere (e.g., reads from a listen socket).
   Signature preserved so original vulnerable flow is unchanged. */
void fill_command_from_listen_socket(char **command_ptr);

/* Main vulnerable function: preserves original vulnerable behavior and dangerous calls. */
void vulnerable_network_handler(void)
{
    unsigned int result_code;
    FILE *process_stream;
    char *command_ptr;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long saved_stack_guard;

    /* Preserve stack protector value as in original binary */
    saved_stack_guard = __stack_chk_guard;

    /* Initialize buffer and set command prefix ("ls ") */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    command_ptr = command_buffer;

    /* Call out to helper that populates command_ptr (vulnerable input source) */
    fill_command_from_listen_socket(&command_ptr);

    /* Invoke system command via popen with the (potentially tainted) command string */
    process_stream = popen(command_ptr, "w");
    if (process_stream != NULL) {
        result_code = pclose(process_stream);
        process_stream = (FILE *)(uintptr_t)result_code;
    }

    /* Stack protector check, preserved exactly */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail(process_stream);
    }

    return;
}