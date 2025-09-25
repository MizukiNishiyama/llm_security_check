#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

/* Constants (magic numbers from original code) */
#define CMD_BUFFER_SIZE 100

/* Simulated stack check guard symbols (preserve original control flow) */
long STACK_CHK_GUARD = 0x0;
void __stack_chk_fail(void *arg)
{
    /* Original code would call stack check failure routine */
    /* Keep as simple termination to preserve flow */
    (void)arg;
    abort();
}

/* Neutral logging function (keeps original call/return behavior) */
unsigned long log_message(unsigned long param)
{
    unsigned int ret;
    if (param != 0) {
        /* original used printf with a format string */
        ret = printf("%s\n");
        param = (unsigned long)ret;
    }
    return param;
}

/* Core function that builds a command and executes it via popen/pclose */
void execute_from_file(void)
{
    unsigned int exit_code;
    size_t current_len;
    FILE *file;
    char *fget_ret;
    char command_buffer[CMD_BUFFER_SIZE];
    long local_canary;

    /* preserve stack guard semantics from original */
    local_canary = STACK_CHK_GUARD;

    /* initialize command buffer */
    memset(command_buffer, 0, CMD_BUFFER_SIZE);

    /* original code set first bytes to "ls " */
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    /* conditional reading from /tmp/file.txt and appending to command buffer */
    if ((1) /* _globalTrue in original is non-zero; keep as always-true */) {
        current_len = strlen(command_buffer);
        if (1 < (int)(CMD_BUFFER_SIZE - current_len)) {
            file = fopen("/tmp/file.txt", "r");
            if (file != NULL) {
                fget_ret = fgets(command_buffer + current_len,
                                  (int)(CMD_BUFFER_SIZE - (int)current_len),
                                  file);
                if (fget_ret == NULL) {
                    /* preserve original behavior: call logging routine on fgets failure */
                    log_message((unsigned long)"fgets() failed");
                    command_buffer[current_len] = '\0';
                }
                fclose(file);
            }
        }
    }

    /* execute constructed command using popen and pclose (vulnerable behavior retained) */
    file = popen(command_buffer, "w");
    if (file != NULL) {
        exit_code = pclose(file);
        file = (FILE *)(unsigned long)exit_code;
    }

    /* stack guard check as in original */
    if (STACK_CHK_GUARD == local_canary) {
        return;
    }

    __stack_chk_fail(file);
}

/* Worker function that seeds RNG, logs, runs core function, then logs again */
unsigned int main_worker(void)
{
    time_t t;
    t = time(NULL);
    srand((unsigned int)t);
    log_message((unsigned long)"Calling ...");
    execute_from_file();
    log_message((unsigned long)"Finished ");
    return 0;
}

/* Optional main to tie things together (keeps file as single translation unit) */
int main(void)
{
    return (int)main_worker();
}