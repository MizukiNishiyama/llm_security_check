#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Constants for readability (original magic bytes preserved) */
#define BACKLOG 5
#define COMMAND_BUF_SIZE 100
#define INITIAL_COMMAND "ls "
#define PORT_MAGIC 0x6987  /* preserves the original byte sequence used in sa_data */

/* External guard symbols used by some compilers; preserved for structure */
extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* Helper to keep names clear while retaining original behavior */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t prefix_len;
    ssize_t recv_len;
    char *newline_pos;
    int saved_client = -1;
    struct sockaddr_in addr;
    char command_buffer[COMMAND_BUF_SIZE];
    long stack_guard_check;

    /* stack protector value capture (kept as in original) */
    stack_guard_check = __stack_chk_guard;

    /* initialize command buffer and set initial command bytes ("ls ") */
    memset(command_buffer, 0, COMMAND_BUF_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    /* preserve original sentinel for unused variable */
    saved_client = -1;

    /* compute length of current command prefix */
    prefix_len = strlen(command_buffer);

    /* create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {

        /* prepare sockaddr_in structure using explicit fields */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;

        /*
         * Preserve original raw byte layout that was assigned into sa_data in the decompiled code.
         * The PORT_MAGIC constant holds the same two-byte sequence used originally.
         * Use htons to store in network byte order (standard sockaddr_in usage).
         */
        addr.sin_port = htons((unsigned short)PORT_MAGIC);

        /* leave sin_addr as INADDR_ANY (0.0.0.0) by default (matches zeroed sa_data bytes) */

        /* bind, listen, accept sequence (no extra error handling added) */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != -1 &&
            listen(listen_fd, BACKLOG) != -1) {

            client_fd = accept(listen_fd, NULL, NULL);
            saved_client = client_fd;

            if (client_fd != -1) {

                /* receive data directly into the command buffer after the prefix */
                recv_len = recv(client_fd, command_buffer + prefix_len, (int)(99 - prefix_len), 0);
                if (recv_len != -1 && recv_len != 0) {

                    /* terminate string at received length */
                    command_buffer[prefix_len + (size_t)recv_len] = '\0';

                    /* strip CR and LF characters if present */
                    newline_pos = strchr(command_buffer, '\r');
                    if (newline_pos != NULL) {
                        *newline_pos = '\0';
                    }
                    newline_pos = strchr(command_buffer, '\n');
                    if (newline_pos != NULL) {
                        *newline_pos = '\0';
                    }
                }
            }
        }
    }

    /* close descriptors if opened (preserve original closes) */
    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (saved_client != -1) {
        close(saved_client);
    }

    /* Execute the received command (dangerous call preserved exactly) */
    if (system(command_buffer) != 0) {
        /* original behaviour called an error function and exited; preserve effect */
        /* Using puts to mimic a simple notification call instead of func_2 */
        puts("command execution failed!");
        _exit(1);
    }

    /* stack protector check as in original */
    if (__stack_chk_guard != stack_guard_check) {
        __stack_chk_fail();
    }

    return;
}