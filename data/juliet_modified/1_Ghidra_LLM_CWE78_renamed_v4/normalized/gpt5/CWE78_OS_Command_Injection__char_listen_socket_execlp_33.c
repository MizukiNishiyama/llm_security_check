#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 100
#define PORT 0x8769

/* Helper that mimics a simple search for a character in a string (returns pointer or NULL) */
static char *find_char(char *s, int c)
{
    return strchr(s, c);
}

/* Main vulnerable routine (preserves original vulnerable behavior) */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int accept_fd;
    size_t prefix_len;
    ssize_t received;
    char command_buffer[BUFFER_SIZE];
    struct sockaddr_in addr;
    int dummy_flag = -1;

    /* initialize buffer with a small command prefix "ls " */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    prefix_len = strlen(command_buffer);

    /* create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {
        /* prepare sockaddr_in structure (uses same port bytes as original) */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short)PORT);
        addr.sin_addr.s_addr = INADDR_ANY;

        /* bind, listen, accept - preserve original control flow and lack of extra checks */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != -1 &&
            listen(listen_fd, 5) != -1 &&
            (accept_fd = accept(listen_fd, NULL, NULL)) != -1) {

            /* receive data directly into the command buffer after the prefix */
            received = recv(accept_fd, command_buffer + prefix_len, (int)(BUFFER_SIZE - 1 - prefix_len), 0);
            if (received != -1 && received != 0) {
                /* null-terminate based on number of bytes received (preserves original integer casts) */
                command_buffer[prefix_len + (size_t)((int)received / 1)] = '\0';

                /* remove CR and LF if present by locating them and replacing with NUL */
                char *p = find_char(command_buffer, '\r');
                if (p != NULL) {
                    *p = '\0';
                }
                p = find_char(command_buffer, '\n');
                if (p != NULL) {
                    *p = '\0';
                }
            }

            /* preserve accept fd for later closing */
            dummy_flag = accept_fd;
        }
    }

    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (dummy_flag != -1) {
        close(dummy_flag);
    }

    /* launch a shell using execlp (keeps the original dangerous call and its arguments) */
    execlp("sh", "sh");

    return;
}

/* simple main to invoke the vulnerable handler (kept minimal) */
int main(void)
{
    vulnerable_network_handler();
    return 0;
}