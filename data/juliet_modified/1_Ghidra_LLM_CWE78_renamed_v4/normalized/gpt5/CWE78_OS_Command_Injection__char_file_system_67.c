#include <stdio.h>
#include <string.h>
#include <stddef.h>

/* Constants for readability (preserve original numeric values) */
#define BUFFER_SIZE 100
#define INPUT_FILE_PATH "/tmp/file.txt"

/* External symbols for stack protector (kept as in original control flow) */
extern unsigned long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Forward declarations of external functions used by the original code.
   These are left as calls with original semantics. */
void func_2(char *buf); /* original external processing function */
void func_3(const char *msg); /* original external error reporting */

/* Renamed function preserving original behavior and vulnerabilities.
   - Uses same buffer size and same unsafe functions (fopen, fgets).
   - No additional checks or error handling added. */
void vulnerable_file_reader(void)
{
    size_t current_len;
    FILE *input_file;
    char *fgets_result;
    char command_buffer[BUFFER_SIZE];
    unsigned long saved_guard;

    /* Save stack guard value for later integrity check */
    saved_guard = __stack_chk_guard;

    /* Initialize buffer and set initial bytes (kept as in original) */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    /* Compute current length of buffer */
    current_len = strlen(command_buffer);

    /* Attempt to read from a file into the buffer (potential overflow preserved) */
    if ((1 < (int)(BUFFER_SIZE - current_len)) &&
        (input_file = fopen(INPUT_FILE_PATH, "r"), input_file != NULL)) {

        fgets_result = fgets(command_buffer + current_len,
                             BUFFER_SIZE - (int)current_len,
                             input_file);

        if (fgets_result == NULL) {
            /* Call out to external function as in original */
            func_3("fgets() failed");
            command_buffer[current_len] = '\0';
        }

        fclose(input_file);
    }

    /* Pass buffer to external processing function (original control flow) */
    func_2(command_buffer);

    /* Stack protector check (preserved) */
    if (__stack_chk_guard == saved_guard) {
        return;
    }

    __stack_chk_fail();
}