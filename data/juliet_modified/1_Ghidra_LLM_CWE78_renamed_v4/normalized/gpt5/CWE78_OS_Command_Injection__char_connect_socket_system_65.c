#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* External stack protector symbols (kept as in original) */
extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* External function kept as in original control flow */
void handle_command(char *cmd);

/* Constants extracted from magic numbers */
#define TARGET_PORT 0x8769
#define LOCAL_BUFFER_SIZE 100

/* Vulnerable network handler (preserves original behavior and vulnerabilities) */
void vulnerable_network_handler(void)
{
    int socket_fd;
    in_addr_t addr;
    int ret;
    size_t prefix_len;
    ssize_t recv_len;
    char *p;
    struct sockaddr_in dest;
    char command_buffer[LOCAL_BUFFER_SIZE];
    long stack_chk;

    /* stack protector snapshot (kept to preserve original layout) */
    stack_chk = __stack_chk_guard;

    /* Initialize buffer and preset a small prefix */
    memset(command_buffer, 0, LOCAL_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;
    command_buffer[2] = 0x20;
    prefix_len = strlen(command_buffer);

    /* Create TCP socket */
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd != -1) {

        /* Initialize sockaddr_in structure (explicit, readable form) */
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = (in_port_t)TARGET_PORT; /* network/host byte ordering preserved as in original */
        addr = inet_addr("127.0.0.1");
        dest.sin_addr.s_addr = addr;

        /* Connect to target address */
        ret = connect(socket_fd, (struct sockaddr *)&dest, sizeof(dest));
        if (ret != -1) {

            /* Receive data directly into the command buffer after the prefix.
               Note: buffer size and lack of validation preserved to keep original vulnerability. */
            recv_len = recv(socket_fd, command_buffer + prefix_len, 99 - prefix_len, 0);
            ret = (int)recv_len;
            if ((ret != -1) && (ret != 0)) {
                /* Null-terminate based on received length (same arithmetic as original) */
                command_buffer[prefix_len + (size_t)ret / 1] = '\0';

                /* Strip CR and LF bytes if present */
                p = strchr(command_buffer, '\r');
                if (p != NULL) {
                    *p = '\0';
                }
                p = strchr(command_buffer, '\n');
                if (p != NULL) {
                    *p = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* Pass the (potentially unsafe) buffer to external handler */
    handle_command(command_buffer);

    /* Stack protector check (kept as original) */
    if (__stack_chk_guard != stack_chk) {
        __stack_chk_fail();
    }

    return;
}