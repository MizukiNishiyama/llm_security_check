#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Constants (magic numbers made explicit) */
#define COMMAND_BUFFER_SIZE 100
#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 0x8769   /* preserved original port value */
#define REMOTE_SOCKADDR_LEN 0x10

/* Forward declarations */
unsigned long log_message(unsigned long msg_ptr);
char *fetch_remote_data_append(char *buffer);
void spawn_shell_with_command(void);
int entry_point(void);

/* Log a short message (wrapper around printf) */
unsigned long log_message(unsigned long msg_ptr)
{
    unsigned int res;

    if (msg_ptr != 0) {
        /* Print a message followed by newline */
        res = printf("%s\n");
        return (unsigned long)res;
    }
    return 0;
}

/* Connect to a local TCP service and append received bytes to buffer.
   Buffer size and lack of validation are preserved from original. */
char *fetch_remote_data_append(char *buffer)
{
    size_t current_len;
    unsigned int sockfd;
    unsigned int connect_res;
    int recv_res;
    struct sockaddr_in addr;
    char *crpos;
    char *lfpos;

    /* Determine current string length in buffer */
    current_len = strlen(buffer);

    /* Create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    sockfd = (unsigned int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd != (unsigned int)-1) {
        /* Prepare sockaddr_in structure for connect */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        /* preserve numeric port value (htons used to place into network order) */
        addr.sin_port = (in_port_t)htons((unsigned short)REMOTE_PORT);
        addr.sin_addr.s_addr = inet_addr(REMOTE_ADDR);

        /* Attempt to connect; original used length 0x10 */
        connect_res = (unsigned int)connect((int)sockfd, (struct sockaddr *)&addr, REMOTE_SOCKADDR_LEN);

        if (connect_res != (unsigned int)-1) {
            /* Receive up to (99 - current_len) bytes directly into the buffer */
            /* Note: no bounds checking beyond this size is performed (preserved) */
            recv_res = (int)recv((int)sockfd, buffer + current_len, 99 - current_len, 0);

            if ((recv_res != -1) && (recv_res != 0)) {
                /* Null-terminate after received bytes (exact arithmetic preserved) */
                buffer[current_len + (size_t)recv_res / 1] = '\0';

                /* Strip CR if present */
                crpos = strchr(buffer, '\r');
                if (crpos != NULL) {
                    *crpos = '\0';
                }

                /* Strip LF if present */
                lfpos = strchr(buffer, '\n');
                if (lfpos != NULL) {
                    *lfpos = '\0';
                }
            }
        }

        /* Close socket (result ignored, as in original) */
        (void)close((int)sockfd);
    }

    return buffer;
}

/* Prepare a command buffer, request remote data to append, then spawn a shell */
void spawn_shell_with_command(void)
{
    char command_buffer[COMMAND_BUFFER_SIZE];
    /* Initialize local buffer to zeros */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Set initial bytes to "ls " (preserving original characters) */
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Append remote data into the buffer (vulnerable behavior preserved) */
    fetch_remote_data_append(command_buffer);

    /* Execute a shell (call preserved exactly as in original) */
    execlp("sh", "sh");
}

/* Entry point: seed RNG, log, call vulnerable function, log */
int entry_point(void)
{
    time_t t;

    t = time(NULL);
    srand((unsigned int)t);

    log_message((unsigned long)"Calling ...");
    spawn_shell_with_command();
    log_message((unsigned long)"Finished ");

    return 0;
}

/* main delegates to entry_point to match original behavior */
int main(void)
{
    return entry_point();
}