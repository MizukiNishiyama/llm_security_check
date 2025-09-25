#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* External symbols used for stack protection in original binary */
extern void *__stack_chk_guard;
extern void __stack_chk_fail(void *);

/* Forward declaration of an external function that fills the command buffer.
   Signature preserved: it takes a pointer to a char* and may modify it. */
void receive_command_over_network(char **command_ptr);

/* Constants for magic numbers made explicit */
#define COMMAND_BUFFER_SIZE 100

/* A function that constructs a command string, allows external modification,
   then executes it with popen/pclose. Original unsafe behavior preserved. */
void vulnerable_network_command_executor(void)
{
    uint32_t close_result;
    FILE *pipe;
    char *command_ptr;
    char command_buffer[COMMAND_BUFFER_SIZE];
    void *stack_guard_local;

    /* Preserve original stack guard check behavior */
    stack_guard_local = *(void **)&__stack_chk_guard;

    /* Initialize the command buffer to zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Prepare initial command prefix: "ls " */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    command_buffer[3] = '\0';

    /* Point command_ptr to the buffer and allow external input to modify it */
    command_ptr = command_buffer;
    receive_command_over_network(&command_ptr);

    /* Execute the potentially modified command string using popen */
    pipe = popen(command_ptr, "w");
    if (pipe != NULL) {
        close_result = pclose(pipe);
        pipe = (FILE *)(uintptr_t)close_result;
    }

    /* Stack guard integrity check preserved as in original */
    if (*(void **)&__stack_chk_guard != stack_guard_local) {
        __stack_chk_fail(pipe);
    }

    return;
}