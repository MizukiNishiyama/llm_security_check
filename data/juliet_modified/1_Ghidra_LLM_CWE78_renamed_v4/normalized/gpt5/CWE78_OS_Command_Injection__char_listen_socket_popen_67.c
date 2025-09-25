#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* Forward declaration of the downstream function (kept as call target). */
void execute_command(char *command);

/* Port and sizes defined as constants for readability (original numeric values preserved). */
#define BACKLOG 5
#define COMMAND_BUFFER_SIZE 100
#define SOCKADDR_IN_LEN 0x10

/* Network handler that preserves original control flow and vulnerabilities. */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t base_len;
    ssize_t recv_len;
    char *found;
    int client_fd_init = -1;
    struct sockaddr_in addr;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long stack_guard_saved;

    /* Stack protector value saved (preserves original check structure). */
    stack_guard_saved = __stack_chk_guard;

    /* Initialize command buffer and set initial contents "ls " (as in original). */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    client_fd = -1;

    base_len = strlen(command_buffer);

    /* Create a TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP). */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {

        /* Construct sockaddr_in with same raw byte values as original sockaddr manipulation.
           Bytes from original sa_data were preserved by composing the port from those bytes. */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;

        /* Original code set sa_data[0] = 'i' (0x69) and sa_data[1] = -0x79 (0x87).
           Compose the 16-bit port value using those bytes in network order. */
        unsigned short port_network_order = (unsigned short)((0x69 << 8) | 0x87);
        addr.sin_port = htons(ntohs(port_network_order)); /* preserve byte pattern */

        /* sin_addr left as INADDR_ANY (zero bytes) to match original zeroed sa_data[2..5]. */

        /* Bind, listen, accept sequence retained without additional checks or validation. */
        if (bind(listen_fd, (struct sockaddr *)&addr, SOCKADDR_IN_LEN) != -1) {
            if (listen(listen_fd, BACKLOG) != -1) {
                client_fd = accept(listen_fd, NULL, NULL);
                if (client_fd != -1) {
                    /* Receive data into the buffer after existing "ls " content.
                       Buffer size parameters are preserved to keep potential overflow behavior. */
                    recv_len = recv(client_fd, command_buffer + base_len, COMMAND_BUFFER_SIZE - 1 - base_len, 0);
                    if ((int)recv_len != -1 && (int)recv_len != 0) {
                        /* Null-terminate based on received length (original arithmetic preserved). */
                        command_buffer[base_len + (ulong)(long)((int)recv_len) / 1] = '\0';

                        /* Strip carriage return and newline if present (in-place). */
                        found = strchr(command_buffer, '\r');
                        if (found != NULL) {
                            *found = '\0';
                        }
                        found = strchr(command_buffer, '\n');
                        if (found != NULL) {
                            *found = '\0';
                        }
                    }
                }
            }
        }
    }

    /* Close descriptors if they were opened (preserve original conditional closes). */
    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (client_fd != -1) {
        close(client_fd);
    }

    /* Call into downstream function with the potentially tainted command buffer. */
    execute_command(command_buffer);

    /* Stack protector check preserved exactly. */
    if (__stack_chk_guard != stack_guard_saved) {
        __stack_chk_fail();
    }

    return;
}

/* Placeholder for the original downstream function; implementation not provided here.
   Kept as an external symbol to preserve original call semantics. */
void execute_command(char *command)
{
    /* Original behavior is preserved elsewhere; this is a stub to allow compilation. */
    (void)command;
}