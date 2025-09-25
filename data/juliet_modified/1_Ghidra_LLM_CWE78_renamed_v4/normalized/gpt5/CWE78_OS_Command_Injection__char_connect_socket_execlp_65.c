#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 0x8769
#define BUFFER_SIZE 100

/* External symbols used for stack protector checks (preserved behavior) */
extern long __stack_chk_guard;
void ___stack_chk_fail(void);

/* Placeholder for external function invoked with the buffer (preserved) */
void func_2(char *data);

/* Network handler with kept vulnerabilities but improved readability */
void vulnerable_network_handler(void)
{
    int socket_fd;
    in_addr_t addr;
    int connect_result;
    size_t prefix_len;
    ssize_t recv_len;
    char *newline_ptr;
    struct sockaddr_in server_addr;
    char command_buffer[BUFFER_SIZE];
    long saved_stack_guard;

    /* preserve stack guard value for later integrity check */
    saved_stack_guard = __stack_chk_guard;

    /* initialize buffer and place a short prefix ("ls ") */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    prefix_len = strlen(command_buffer);

    /* create a TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (socket_fd != -1) {
        /* prepare sockaddr_in structure for 127.0.0.1:PORT */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons((uint16_t)PORT);
        addr = inet_addr("127.0.0.1");
        server_addr.sin_addr.s_addr = (in_addr_t)addr;

        /* attempt to connect to the remote endpoint */
        connect_result = connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (connect_result != -1) {
            /* receive data directly into the buffer after the prefix */
            recv_len = recv(socket_fd, command_buffer + prefix_len, (int)(BUFFER_SIZE - prefix_len - 1), 0);
            if ((int)recv_len != -1 && (int)recv_len != 0) {
                /* null-terminate based on received length */
                command_buffer[prefix_len + (size_t)recv_len] = '\0';

                /* strip CR and LF characters if present */
                newline_ptr = strchr(command_buffer, '\r');
                if (newline_ptr != NULL) {
                    *newline_ptr = '\0';
                }
                newline_ptr = strchr(command_buffer, '\n');
                if (newline_ptr != NULL) {
                    *newline_ptr = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* pass the (potentially tainted) buffer to external function */
    func_2(command_buffer);

    /* preserve original stack check behavior */
    if (__stack_chk_guard != saved_stack_guard) {
        ___stack_chk_fail();
    }

    return;
}