#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 100
#define ENV_VAR_NAME "ADD"

/* Prototypes for nonstandard/checking variants present in original binary */
char *strncat_chk(char *dest, const char *src, size_t n, size_t guard);

/* Stack protector symbols kept to mirror original control flow (no protection added) */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Build a command buffer from a fixed prefix and environment variable, then invoke /bin/sh.
   Note: This function intentionally preserves the original unsafe behavior (no checks,
   direct use of dangerous functions) to maintain the vulnerability semantics. */
void vulnerable_shell_exec(void)
{
    int execl_ret;
    size_t prefix_len;
    char *env_value;
    char command_buffer[BUFFER_SIZE];
    long local_canary;

    /* Preserve original stack guard read */
    local_canary = __stack_chk_guard;

    /* Initialize buffer and set fixed prefix "ls " */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    /* Compute current length of prefix */
    prefix_len = strlen(command_buffer);

    /* Append environment variable content if present (no validation) */
    env_value = getenv(ENV_VAR_NAME);
    if (env_value != NULL) {
        /* Original used a checked variant with an extra guard parameter; keep call shape */
        strncat_chk(command_buffer + prefix_len, env_value, (size_t)(BUFFER_SIZE - 1 - prefix_len), (size_t)-1);
    }

    /* Call /bin/sh using execl with the original argument pattern (no terminating NULL passed) */
    execl_ret = execl("/bin/sh", "/bin/sh");

    /* Preserve original stack guard check and failure call path */
    if (__stack_chk_guard != local_canary) {
        __stack_chk_fail(execl_ret);
    }

    return;
}

/* Seed RNG, print messages, and invoke the vulnerable routine */
int main_flow(void)
{
    time_t now;

    now = time((time_t *)NULL);
    srand((unsigned int)now);

    /* Print a message if provided (original used a call with a format string only) */
    print_message("Calling ...");
    vulnerable_shell_exec();
    print_message("Finished ");

    return 0;
}

/* Print a string followed by newline if parameter is nonzero.
   Kept semantics similar to original (uses printf). */
unsigned long print_message(unsigned long param)
{
    unsigned int written;

    if (param != 0) {
        written = printf("%s\n");
        param = (unsigned long)written;
    }
    return param;
}

/* Minimal stub to match the original checked strncat signature.
   It forwards to standard strncat without additional checks to preserve behavior. */
char *strncat_chk(char *dest, const char *src, size_t n, size_t guard)
{
    (void)guard; /* unused but kept to match original signature */
    /* Use standard strncat semantics: ensure there is at most n characters appended.
       Note: Caller may pass a destination pointer not to the buffer start; preserved. */
    /* Temporarily create a buffer pointer consistent with strncat expectations */
    return strncat(dest, src, n);
}