#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

/* Constants to replace magic numbers */
#define BACKLOG 5
#define BUFFER_SIZE 100
#define INITIAL_COMMAND "ls "
#define PORT_BE 0x6987 /* Big-endian raw port bytes from original sockaddr.sa_data[0..1] */

/* External symbols preserved from original binary */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void);
extern void func_2(void *);

/* Vulnerable network handler: preserves original control flow and vulnerabilities */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t prefix_len;
    ssize_t recv_len;
    char *nl_ptr;
    int saved_client_fd;
    struct sockaddr_in addr;
    char command_buffer[BUFFER_SIZE];
    unsigned char stack_area[16];
    char *buffer_ptr;
    long stack_chk;

    /* Stack protector value preserved */
    stack_chk = __stack_chk_guard;

    /* Initialize buffer and set initial command prefix ("ls ") */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    saved_client_fd = -1;

    /* Compute length of initial prefix */
    prefix_len = strlen(command_buffer);

    /* Create socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {

        /* Zero and set up sockaddr_in similarly to original sockaddr manipulation */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;

        /* Preserve original raw port bytes by constructing big-endian port value then htons */
        addr.sin_port = htons((uint16_t)PORT_BE);

        /* Bind, listen, accept sequence preserved as in original */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != -1 &&
            listen(listen_fd, BACKLOG) != -1 &&
            (saved_client_fd = accept(listen_fd, (struct sockaddr *)NULL, (socklen_t *)NULL)) != -1) {

            /* Receive data into command_buffer after the prefix; buffer size arithmetic preserved */
            recv_len = recv(saved_client_fd, command_buffer + prefix_len, BUFFER_SIZE - 1 - prefix_len, 0);
            client_fd = (int)recv_len;
            if (client_fd != -1 && client_fd != 0) {
                /* Preserve original null-termination computation including redundant casts/divisions */
                command_buffer[prefix_len + (unsigned long)(long)client_fd / 1] = '\0';

                /* Strip CR and LF if present (original used strchr and replaced with NUL) */
                nl_ptr = strchr(command_buffer, '\r');
                if (nl_ptr != NULL) {
                    *nl_ptr = '\0';
                }
                nl_ptr = strchr(command_buffer, '\n');
                if (nl_ptr != NULL) {
                    *nl_ptr = '\0';
                }
            }
        }
    }

    /* Close descriptors if opened (preserve original cleanup behavior) */
    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (saved_client_fd != -1) {
        close(saved_client_fd);
    }

    /* Pass stack_area to external function as in original */
    buffer_ptr = command_buffer;
    func_2(stack_area);

    /* Stack protector check preserved */
    if (__stack_chk_guard != stack_chk) {
        __stack_chk_fail();
    }

    return;
}