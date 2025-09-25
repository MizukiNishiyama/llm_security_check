#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* External stack protector symbols (kept as in original decompiled code) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(int);

/* Preserved global flag from original binary */
#define GLOBAL_FLAG_VALUE 5

/* Buffer size constants */
#define RAW_BUFFER_SIZE 101
#define INPUT_AREA_OFFSET 1
#define INPUT_AREA_SIZE 100

/* Function declarations (renamed for clarity while preserving behavior) */
void vulnerable_network_handler(void);
int orchestrator(void);
unsigned long print_wrapper(unsigned long param);

/* Implementation */

/* 
   vulnerable_network_handler:
   - Prepares a command buffer with an initial "ls " at offset 1
   - Optionally appends data read from stdin when GLOBAL_FLAG_VALUE == 5
   - Calls execl("/bin/sh", "/bin/sh"); (kept as in original)
   - Preserves original stack protector checks
*/
void vulnerable_network_handler(void)
{
    char *input_ptr;
    int execl_ret;
    size_t cur_len;
    char *fgets_ret;
    char raw_buffer[RAW_BUFFER_SIZE];
    long saved_canary;

    /* Save stack protector value */
    saved_canary = __stack_chk_guard;

    /* Point to buffer area starting at offset 1 and clear INPUT_AREA_SIZE bytes */
    input_ptr = raw_buffer + INPUT_AREA_OFFSET;
    memset(input_ptr, 0, INPUT_AREA_SIZE);

    /* Place characters 'l','s',' ' at positions 1,2,3 respectively */
    raw_buffer[1] = 0x6c; /* 'l' */
    raw_buffer[2] = 0x73; /* 's' */
    raw_buffer[3] = 0x20; /* ' ' */

    /* Conditional read from stdin similar to original logic */
    if ((GLOBAL_FLAG_VALUE == 5) && (cur_len = strlen(input_ptr), 1 < (INPUT_AREA_SIZE - cur_len))) {
        fgets_ret = fgets(input_ptr + cur_len, (int)(INPUT_AREA_SIZE - cur_len), stdin);
        if (fgets_ret == NULL) {
            /* Preserve original behavior: call print wrapper and terminate branch as decompiled code did */
            print_wrapper((unsigned long)"fgets() failed");
            input_ptr[cur_len] = '\0';
        } else {
            cur_len = strlen(input_ptr);
            if ((cur_len != 0) && (input_ptr[cur_len - 1] == '\n')) {
                input_ptr[cur_len - 1] = '\0';
            }
        }
    }

    /* Call execl as in the original code (arguments preserved) */
    execl_ret = execl("/bin/sh", "/bin/sh");

    /* Stack protector check preserved */
    if (__stack_chk_guard == saved_canary) {
        return;
    }

    __stack_chk_fail(execl_ret);
}

/*
  orchestrator:
  - Seeds PRNG with current time
  - Calls print_wrapper before and after invoking vulnerable_network_handler
*/
int orchestrator(void)
{
    time_t t;

    t = time((time_t *)0x0);
    srand((unsigned int)t);

    print_wrapper((unsigned long)"Calling ...");
    vulnerable_network_handler();
    print_wrapper((unsigned long)"Finished ");

    return 0;
}

/*
  print_wrapper:
  - If param is non-zero, calls printf with a format string but without supplying
    the expected argument, preserving the original decompiled behavior.
*/
unsigned long print_wrapper(unsigned long param)
{
    unsigned int ret;

    if (param != 0) {
        ret = printf("%s\n");
        param = (unsigned long)ret;
    }
    return param;
}

/* Minimal main to allow compilation if desired (not present in original) */
/* int main(void) { return orchestrator(); } */