#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* Constants and minimal globals to mirror original behavior */
#define BUFFER_SIZE 100
#define GLOBAL_CONST_FIVE 5

extern uintptr_t __stack_chk_guard;
extern void __stack_chk_fail(void *);

/* Forward declarations */
unsigned long print_message(unsigned long param);
void vulnerable_exec_from_file(void);
unsigned int run_sequence(void);

/* 
 * Reads from /tmp/file.txt into a local command buffer (no bounds check beyond original),
 * then passes that buffer to popen. Behavior mirrors original logic and retains unsafe calls.
 */
void vulnerable_exec_from_file(void)
{
    uint32_t return_code;
    size_t current_len;
    FILE *fp;
    char *fgets_ret;
    char command_buffer[BUFFER_SIZE];
    uintptr_t local_guard;

    /* stack protector snapshot (kept as in original) */
    local_guard = __stack_chk_guard;

    /* initialize buffer */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;   /* 's' */
    command_buffer[2] = 0x20;   /* ' ' */

    /* condition matches original: check constant and available space before reading file */
    if ((GLOBAL_CONST_FIVE == 5) &&
        (current_len = strlen(command_buffer), 1 < (BUFFER_SIZE - current_len)) &&
        (fp = fopen("/tmp/file.txt", "r"), fp != NULL)) {

        /* read from file into remaining portion of buffer (keeps original behavior) */
        fgets_ret = fgets(command_buffer + current_len, (int)(BUFFER_SIZE - (int)current_len), fp);
        if (fgets_ret == NULL) {
            /* original called func_2("fgets() failed") and then restored terminator */
            print_message((unsigned long)"fgets() failed");
            command_buffer[current_len] = '\0';
        }
        fclose(fp);
    }

    /* execute the constructed command via popen (unsafe call preserved) */
    fp = popen(command_buffer, "w");
    if (fp != NULL) {
        return_code = (uint32_t)pclose(fp);
        fp = (FILE *)(uintptr_t)return_code;
    }

    /* stack protector check preserved */
    if (__stack_chk_guard == local_guard) {
        return;
    }

    __stack_chk_fail(fp);
}

/* 
 * Initializes RNG based on current time, prints messages, and calls vulnerable handler.
 * Keeps original sequence and lack of additional error handling.
 */
unsigned int run_sequence(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);
    print_message((unsigned long)"Calling ...");
    vulnerable_exec_from_file();
    print_message((unsigned long)"Finished ");
    return 0;
}

/* 
 * Prints a message if param is non-zero. Intentionally mirrors original flawed printf usage
 * (prints with "%s\n" without passing a corresponding argument when invoked with non-zero).
 */
unsigned long print_message(unsigned long param)
{
    unsigned int printed;

    if (param != 0) {
        printed = printf("%s\n");
        param = (unsigned long)printed;
    }
    return param;
}

/* Minimal main to allow linking when desired (optional). */
/* int main(void) { return run_sequence(); } */