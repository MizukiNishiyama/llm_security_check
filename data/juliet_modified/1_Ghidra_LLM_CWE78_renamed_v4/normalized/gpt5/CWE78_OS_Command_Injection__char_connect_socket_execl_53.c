#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SERVER_PORT 0x8769
#define SERVER_ADDR "127.0.0.1"
#define COMMAND_BUFFER_SIZE 100

extern long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Prototype preserved from original binary */
void func_2(char *command);

/* Renamed for clarity; original vulnerabilities and calls are preserved. */
void vulnerable_network_handler(void) {
    int socket_fd;
    int inet_result;
    int recv_result;
    size_t prefix_len;
    ssize_t bytes_received;
    char *newline_pos;
    struct sockaddr_in server_addr;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long stack_guard_saved;

    /* stack protector value read as in original */
    stack_guard_saved = __stack_chk_guard;

    /* initialize buffer as original */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;
    command_buffer[2] = 0x20;
    prefix_len = strlen(command_buffer);

    /* create socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd != -1) {
        /* prepare sockaddr_in using standard fields */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons((in_port_t)SERVER_PORT);
        server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

        /* connect using the original length value (0x10) */
        inet_result = connect(socket_fd, (struct sockaddr *)&server_addr, 0x10);
        if (inet_result != -1) {
            /* receive data directly into command_buffer after the prefix */
            bytes_received = recv(socket_fd, command_buffer + prefix_len, COMMAND_BUFFER_SIZE - 1 - prefix_len, 0);
            recv_result = (int)bytes_received;
            if ((recv_result != -1) && (recv_result != 0)) {
                /* null-terminate as in original */
                command_buffer[prefix_len + (unsigned long)recv_result / 1] = '\0';

                /* strip carriage return if present */
                newline_pos = strchr(command_buffer, 0x0d);
                if (newline_pos != NULL) {
                    *newline_pos = '\0';
                }

                /* strip line feed if present */
                newline_pos = strchr(command_buffer, 10);
                if (newline_pos != NULL) {
                    *newline_pos = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* call preserved function with potentially tainted data */
    func_2(command_buffer);

    /* stack protector check as in original */
    if (__stack_chk_guard != stack_guard_saved) {
        __stack_chk_fail();
    }

    return;
}