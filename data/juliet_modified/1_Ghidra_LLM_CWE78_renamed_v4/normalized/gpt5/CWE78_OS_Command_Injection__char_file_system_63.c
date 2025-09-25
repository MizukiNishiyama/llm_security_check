#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Constants for clarity */
#define CMD_BUFFER_SIZE 100
#define PREFIX_L     'l'
#define PREFIX_S     0x73  /* 's' */
#define PREFIX_SPACE 0x20  /* ' ' */

/* External functions assumed to exist elsewhere in the original binary */
void call_sink(char **command_ptr);  /* originally func_2 */
void log_error(const char *msg);     /* originally func_3 */

/* Stack protector symbols (platform-independent declaration) */
extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* High-level name for the original function func_0 */
void vulnerable_command_builder(void)
{
    size_t current_len;
    FILE *fp;
    char *read_pos;
    char *command_buffer_ptr;
    char command_buffer[CMD_BUFFER_SIZE];
    long saved_canary;

    /* Save stack protector value */
    saved_canary = (long)__stack_chk_guard;

    /* Initialize buffer */
    memset(command_buffer, 0, CMD_BUFFER_SIZE);

    /* Populate buffer with a fixed prefix: "ls " */
    command_buffer[0] = PREFIX_L;
    command_buffer[1] = PREFIX_S;
    command_buffer[2] = PREFIX_SPACE;

    /* Prepare pointer to buffer for further operations */
    command_buffer_ptr = command_buffer;

    /* Measure current length of the buffer */
    current_len = strlen(command_buffer);

    /* If there is at least 2 bytes free, attempt to append contents from file */
    if ((1 < (CMD_BUFFER_SIZE - current_len)) &&
        (fp = fopen("/tmp/file.txt", "r"), fp != NULL)) {

        /* Read from file directly into the remaining buffer space */
        read_pos = fgets(command_buffer_ptr + current_len,
                         CMD_BUFFER_SIZE - (int)current_len,
                         fp);

        /* If fgets fails, restore terminator at previous length */
        if (read_pos == NULL) {
            log_error("fgets() failed");
            command_buffer_ptr[current_len] = '\0';
        }

        fclose(fp);
    }

    /* Pass pointer to buffer to another function (vulnerable sink) */
    call_sink(&command_buffer_ptr);

    /* Verify stack protector and call failure routine on mismatch */
    if ((long)__stack_chk_guard == saved_canary) {
        return;
    }

    __stack_chk_fail();
}