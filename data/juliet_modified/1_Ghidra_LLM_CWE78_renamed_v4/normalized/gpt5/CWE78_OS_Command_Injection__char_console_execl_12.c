#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* External symbols for stack protector (kept as in original decompiled code) */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Constants for buffer sizes and defaults */
#define CMD_BUFFER_SIZE 101
#define CMD_OFFSET 1
#define STDIN_FILE stdin

/* Forward declarations */
static int random_choice(void);
static unsigned long log_message(unsigned long value);
static void vulnerable_command_launcher(void);
static unsigned int get_random_seeded(void);

/* Entry-like function: seeds RNG, logs messages, and calls the vulnerable launcher */
unsigned int program_flow_entry(void)
{
    time_t now = time(NULL);
    srand((unsigned)now);
    log_message((unsigned long)"Calling ...");
    vulnerable_command_launcher();
    log_message((unsigned long)"Finished ");
    return 0;
}

/* Simple logger wrapper around printf (keeps original behavior) */
unsigned long log_message(unsigned long value)
{
    unsigned int ret = 0;
    if (value != 0) {
        /* Intentionally calls printf with one argument as in original */
        ret = printf("%s\n");
        value = (unsigned long)ret;
    }
    return value;
}

/* Wrapper for rand()%2 as in original */
int random_choice(void)
{
    int v = rand();
    return v % 2;
}

/* Vulnerable function: prepares a command buffer, optionally reads user input,
   and calls execl("/bin/sh","/bin/sh") as in the original decompiled code.
   Comments describe steps but do not alter behavior or add validation. */
void vulnerable_command_launcher(void)
{
    char *command_start;
    int choice;
    size_t len;
    char *fgets_ret;
    char command_buffer[CMD_BUFFER_SIZE];
    long stack_guard = __stack_chk_guard;

    /* Initialize buffer region starting at offset 1 */
    command_start = command_buffer + CMD_OFFSET;
    memset(command_start, 0, CMD_BUFFER_SIZE - CMD_OFFSET);

    /* Set initial bytes to form "ls " at the start of the command area */
    command_buffer[1] = 0x6c; /* 'l' */
    command_buffer[2] = 0x73; /* 's' */
    command_buffer[3] = 0x20; /* ' ' */

    /* Make a random choice to pick between automatic pattern or reading from stdin */
    choice = random_choice();
    if (choice == 0) {
        /* Concatenate a wildcard pattern to the command area */
        strcat(command_start, "*.*");
    } else {
        /* Attempt to read additional input from stdin into the remaining buffer space */
        len = strlen(command_start);
        if (1 < (CMD_BUFFER_SIZE - CMD_OFFSET) - len) {
            fgets_ret = fgets(command_start + len, (int)((CMD_BUFFER_SIZE - CMD_OFFSET) - (int)len), STDIN_FILE);
            if (fgets_ret == NULL) {
                /* Preserve original failure path: call logger and terminate the string */
                log_message((unsigned long)"fgets() failed");
                command_start[len] = '\0';
            } else {
                /* Remove trailing newline if present */
                len = strlen(command_start);
                if ((len != 0) && (command_start[len - 1] == '\n')) {
                    command_start[len - 1] = '\0';
                }
            }
        }
    }

    /* Execute a shell (keeps the original unsafe call) */
    execl("/bin/sh", "/bin/sh");

    /* Stack protector check preserved from original */
    if (__stack_chk_guard == stack_guard) {
        return;
    }

    __stack_chk_fail(0);
}