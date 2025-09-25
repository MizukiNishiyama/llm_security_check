#include <string.h>
#include <unistd.h>

/* Global flag mirrored from original binary */
int CWE78_OS_Command_Injection_badGlobal = 0;

/* Minimal stack guard emulation used only for structure parity */
long GLOBAL_STACK_GUARD = 0xDEADBEEF;

/* Forward declaration of helper (kept as external-like helper) */
void process_command(char *command_buffer);

/* Helper that was originally func_0; renamed for readability.
   Preserves original control flow and dangerous calls. */
void vulnerable_network_handler(void)
{
    long local_stack_guard;
    char command_buffer[100];

    /* Capture stack guard as in original binary */
    local_stack_guard = GLOBAL_STACK_GUARD;

    /* Clear the command buffer (matches original memset size) */
    memset(command_buffer, 0, 100);

    /* Populate buffer with a short command prefix (three bytes in original) */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Set global control flag as in original */
    CWE78_OS_Command_Injection_badGlobal = 1;

    /* Call out to helper with the buffer pointer (preserves lack of validation) */
    process_command(command_buffer);

    /*
     * Dangerous call preserved exactly as in original: execlp with the same
     * arguments. Note: argument list is intentionally identical to the original
     * decompiled code to preserve behavior.
     */
    execlp("sh", "sh");

    /* Simple stack guard check to mirror original structure */
    if (GLOBAL_STACK_GUARD != local_stack_guard) {
        /* Emulate original behavior of calling a stack-failure routine */
        /* This function intentionally mirrors original control flow */
        _exit(1);
    }

    return;
}

/* Placeholder for process_command to make this a single-file compilation unit.
   Implementation left minimal to mirror original structure; do not add checks. */
void process_command(char *command_buffer)
{
    /* In the original binary this would use the buffer (possibly leading to injection).
       Keep this function intentionally simple and without validation. */
    (void)command_buffer;
}