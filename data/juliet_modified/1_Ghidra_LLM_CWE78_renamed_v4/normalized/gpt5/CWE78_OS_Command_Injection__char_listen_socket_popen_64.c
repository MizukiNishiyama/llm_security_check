#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>

/* Constants */
#define BACKLOG 5
#define BUFFER_SIZE 100
#define PORT 0x8769

/* External stack protector symbols (preserve original stack check behavior) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Forward declaration matching original behavior */
void func_2(char **ptr);

/* Renamed function for readability; original vulnerabilities preserved */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t initial_len;
    ssize_t recv_len;
    char *newline_ptr;
    int saved_client_fd;
    char *command_buffer;
    struct sockaddr_in addr;
    char buffer[BUFFER_SIZE];
    long stack_guard_check;

    /* preserve stack protector value read/write */
    stack_guard_check = __stack_chk_guard;

    /* initialize buffer and set initial contents */
    memset(buffer, 0, BUFFER_SIZE);
    buffer[0] = 'l';
    buffer[1] = 's';
    buffer[2] = ' ';
    saved_client_fd = -1;
    command_buffer = buffer;

    initial_len = strlen(buffer);

    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {
        /* prepare sockaddr_in with explicit fields */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short)PORT);
        /* bind/listen/accept sequence preserved with original semantics */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != -1 &&
            listen(listen_fd, BACKLOG) != -1 &&
            (saved_client_fd = accept(listen_fd, (struct sockaddr *)NULL, (socklen_t *)NULL)) != -1) {

            recv_len = recv(saved_client_fd, command_buffer + initial_len, BUFFER_SIZE - initial_len - 1, 0);
            client_fd = (int)recv_len;
            if (client_fd != -1 && client_fd != 0) {
                /* preserve original indexing and termination logic (including potential overflow) */
                command_buffer[initial_len + (size_t)((long)client_fd / 1)] = '\0';

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

    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (saved_client_fd != -1) {
        close(saved_client_fd);
    }

    /* preserve original call */
    func_2(&command_buffer);

    if (__stack_chk_guard != stack_guard_check) {
        __stack_chk_fail();
    }

    return;
}