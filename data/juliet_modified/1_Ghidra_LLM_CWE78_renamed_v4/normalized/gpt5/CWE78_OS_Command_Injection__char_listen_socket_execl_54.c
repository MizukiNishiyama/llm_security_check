#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 0x8769
#define BACKLOG 5
#define BUFFER_SIZE 100

extern long __stack_chk_guard;
void __stack_chk_fail(void);
void process_command(char *cmd); /* kept as external/opaque handler */

/* Function: vulnerable_network_handler
 * Description: Listens on a TCP socket, receives data into a fixed-size buffer,
 *              and forwards the buffer to process_command. Structure and checks
 *              mirror the original control flow.
 */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t prefix_len;
    ssize_t recv_len;
    char *newline_ptr;
    int accepted_fd = -1;
    struct sockaddr_in addr;
    char command_buffer[BUFFER_SIZE];
    long stack_guard_saved;

    /* Stack protector snapshot */
    stack_guard_saved = __stack_chk_guard;

    /* Initialize buffer */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    listen_fd = -1;
    prefix_len = strlen(command_buffer);

    /* Create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {

        /* Prepare sockaddr_in structure using explicit fields */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)PORT);
        addr.sin_addr.s_addr = INADDR_ANY;

        /* Bind, listen, accept sequence (no extra validation added) */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != -1) {
            if (listen(listen_fd, BACKLOG) != -1) {
                accepted_fd = accept(listen_fd, NULL, NULL);
                if (accepted_fd != -1) {
                    /* Receive data appended to existing buffer contents */
                    recv_len = recv(accepted_fd, command_buffer + prefix_len, BUFFER_SIZE - 1 - prefix_len, 0);
                    client_fd = (int)recv_len;
                    if ((client_fd != -1) && (client_fd != 0)) {
                        /* Null-terminate using the received length (preserve original computation) */
                        command_buffer[prefix_len + (unsigned long)(long)client_fd / 1] = '\0';

                        /* Strip CR and LF if present (in-place) */
                        newline_ptr = strchr(command_buffer, 0x0d);
                        if (newline_ptr != NULL) {
                            *newline_ptr = '\0';
                        }
                        newline_ptr = strchr(command_buffer, 0x0a);
                        if (newline_ptr != NULL) {
                            *newline_ptr = '\0';
                        }
                    }
                }
            }
        }
    }

    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (accepted_fd != -1) {
        close(accepted_fd);
    }

    /* Forward the buffer to the external handler */
    process_command(command_buffer);

    /* Stack protector check */
    if (__stack_chk_guard != stack_guard_saved) {
        __stack_chk_fail();
    }

    return;
}