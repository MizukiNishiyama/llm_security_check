#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* External stack protector symbols retained to mirror original control flow */
extern long __stack_chk_guard;
extern void __stack_chk_fail(int);

/* Meaningful names for functions and buffers while preserving behavior and vulnerabilities */
void vulnerable_shell_spawn(void)
{
    int return_code;
    size_t current_len;
    char *env_value;
    char command_buffer[100];
    long saved_stack_guard;

    /* Save stack guard value (mirrors original stack protector usage) */
    saved_stack_guard = __stack_chk_guard;

    /* Initialize command buffer and set initial command prefix */
    memset(command_buffer, 0, sizeof(command_buffer));
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Determine current length of the buffer */
    current_len = strlen(command_buffer);

    /* Read environment variable and append it to the command buffer (no validation) */
    env_value = getenv("ADD");
    if (env_value != NULL) {
        /* Append with remaining space calculation preserved exactly as in original */
        strncat(command_buffer + current_len, env_value, (size_t)(99 - current_len));
    }

    /* Invoke shell using execl with same arguments as original (no NULL terminator) */
    return_code = execl("/bin/sh", "/bin/sh");

    /* Verify stack guard and call fail handler if altered (preserved behavior) */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail(return_code);
    }

    return;
}

unsigned long log_message(unsigned long param)
{
    unsigned int printed;

    if (param != 0) {
        /* Call to printf preserved; format string intentionally minimal as in original */
        printed = printf("%s\n");
        param = (unsigned long)printed;
    }
    return param;
}

int main_orchestrator(void)
{
    time_t t;

    /* Seed RNG using current time (preserved original behavior) */
    t = time(NULL);
    srand((unsigned int)t);

    /* Log, call vulnerable routine, log */
    log_message((unsigned long)"Calling ...");
    vulnerable_shell_spawn();
    log_message((unsigned long)"Finished ");

    return 0;
}

/* Provide standard main entry point that calls the orchestrator */
int main(void)
{
    return main_orchestrator();
}