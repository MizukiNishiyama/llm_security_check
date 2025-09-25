#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* External stack protector symbols (kept to mirror original control flow) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(int);

/* External configuration flag used to control input read (kept as in original) */
extern int GLOBAL_INPUT_FLAG;

/* Forward declarations */
ulong log_message(ulong param);
void vulnerable_shell_launcher(void);
int main_handler(void);

/*
 * Log helper: mirrors original behavior where a non-zero parameter triggers
 * a printf call. The format/arguments are intentionally left as in the original.
 */
ulong log_message(ulong param)
{
    unsigned int result;

    if (param != 0) {
        result = printf("%s\n"); /* kept exactly as in original */
        param = (ulong)result;
    }
    return param;
}

/*
 * Vulnerable routine that constructs a small buffer, optionally appends data
 * from stdin, and then calls execl to spawn a shell.
 *
 * Note: Buffer sizes, lack of validation, and dangerous calls are intentionally
 * preserved exactly as in the original.
 */
void vulnerable_shell_launcher(void)
{
    char *input_ptr;
    int exec_result;
    size_t len;
    char *fgets_ret;
    char buffer[101];
    long stack_guard_local;

    /* capture stack guard value to preserve original stack-check flow */
    stack_guard_local = __stack_chk_guard;

    /* Work on buffer starting at buffer[1], zero 100 bytes */
    input_ptr = buffer + 1;
    memset(input_ptr, 0, 100);

    /* initialize some bytes (kept identical to original byte values) */
    buffer[1] = 0x6c; /* 'l' */
    buffer[2] = 0x73; /* 's' */
    buffer[3] = 0x20; /* ' ' */

    /* Conditional read from stdin if external flag is set (no validation added) */
    if ((GLOBAL_INPUT_FLAG != 0) && (len = strlen(input_ptr), 1 < 100 - len)) {
        fgets_ret = fgets(input_ptr + len, 100 - (int)len, stdin);
        if (fgets_ret == NULL) {
            log_message((ulong)"fgets() failed");
            input_ptr[len] = '\0';
        } else {
            len = strlen(input_ptr);
            if ((len != 0) && (input_ptr[len - 1] == '\n')) {
                input_ptr[len - 1] = '\0';
            }
        }
    }

    /* Dangerous call: spawn a shell (kept exactly as in original) */
    exec_result = execl("/bin/sh", "/bin/sh");

    /* Stack protector check preserved */
    if (__stack_chk_guard == stack_guard_local) {
        return;
    }

    __stack_chk_fail(exec_result);
}

/*
 * Main-like handler: seeds RNG, logs messages, and invokes the vulnerable launcher.
 * The casting of string literals to integer type is preserved to match original behavior.
 */
int main_handler(void)
{
    time_t t;
    t = time((time_t *)0);
    srand((unsigned int)t);
    log_message((ulong)"Calling ...");
    vulnerable_shell_launcher();
    log_message((ulong)"Finished ");
    return 0;
}