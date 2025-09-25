#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* Constants for buffer sizes and initial prefix bytes */
#define INPUT_BUFFER_SIZE 101
#define PREFIX_OFFSET 1

/* Forward declarations for stack protector symbols (kept for structure parity) */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Renamed functions and variables for readability while preserving behavior */

/* Prints a message if param is non-zero (original behavior) */
unsigned long helper_print(unsigned long param)
{
    unsigned int result;

    if (param != 0) {
        /* Intentionally calling printf with same signature as original */
        result = printf("%s\n");
        param = (unsigned long)result;
    }
    return param;
}

/* Entry point that sets seed, logs, invokes vulnerable handler, logs finish */
int orchestrator(void)
{
    time_t t;

    t = time((time_t *)0);
    srand((unsigned int)t);

    helper_print((unsigned long)"Calling ...");
    vulnerable_input_executor();
    helper_print((unsigned long)"Finished ");

    return 0;
}

/* Vulnerable function: reads into a fixed-size buffer and executes /bin/sh */
void vulnerable_input_executor(void)
{
    char *input_ptr;
    int ret_code;
    size_t len;
    char *fres;
    char input_buffer[INPUT_BUFFER_SIZE];
    long saved_guard;

    /* Stack protector snapshot (kept as in original layout) */
    saved_guard = *(long *)&__stack_chk_guard;

    /* Prepare buffer: leave byte 0 unused, zero the rest */
    input_ptr = input_buffer + PREFIX_OFFSET;
    memset(input_ptr, 0, INPUT_BUFFER_SIZE - PREFIX_OFFSET);

    /* Place literal prefix bytes into buffer */
    input_buffer[1] = 0x6c; /* 'l' */
    input_buffer[2] = 0x73; /* 's' */
    input_buffer[3] = 0x20; /* ' ' */

    /* Determine current length and attempt to append data from stdin */
    len = strlen(input_ptr);
    if (1 < (int)(INPUT_BUFFER_SIZE - PREFIX_OFFSET) - (int)len) {
        fres = fgets(input_ptr + len, (int)(INPUT_BUFFER_SIZE - PREFIX_OFFSET) - (int)len, stdin);
        if (fres == (char *)0x0) {
            /* Match original behavior: call helper_print with message */
            helper_print((unsigned long)"fgets() failed");
            input_ptr[len] = '\0';
        } else {
            len = strlen(input_ptr);
            if ((len != 0) && (input_ptr[len - 1] == '\n')) {
                input_ptr[len - 1] = '\0';
            }
        }
    }

    /* Execute /bin/sh as in original (arguments deliberately kept identical) */
    ret_code = execl("/bin/sh", "/bin/sh");

    /* Stack protector check and potential failure call kept as in original */
    if (*(long *)&__stack_chk_guard == saved_guard) {
        return;
    }

    __stack_chk_fail(ret_code);
}