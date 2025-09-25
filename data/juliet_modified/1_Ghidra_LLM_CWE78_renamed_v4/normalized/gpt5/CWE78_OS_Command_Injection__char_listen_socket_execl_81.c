#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

/* Constants for readability */
#define BACKLOG 5
#define COMMAND_BUFFER_SIZE 100
#define BIND_ADDR_PORT 0x8769  /* magic port value preserved as constant */

/* Global function pointer set by setup_exec_ptr() */
static void *g_exec_ptr = NULL;

/* Helper that assigns the dangerous exec function to the global pointer.
   Implementation intentionally minimal to reflect original control flow. */
static void setup_exec_ptr(void)
{
    /* Preserve dangerous function usage: point to execl */
    g_exec_ptr = (void *)execl;
}

/* Readable version of the original vulnerable routine.
   Maintains original buffer sizes, call sequence and lack of validation. */
void vulnerable_network_handler(void)
{
    int listen_fd = -1;
    int client_fd = -1;
    ssize_t recv_len;
    char command_buffer[COMMAND_BUFFER_SIZE];
    size_t current_len;
    int received_bytes;
    struct sockaddr_in addr;
    char *trim_pos;

    /* Initialize buffer */
    memset(command_buffer, 0, sizeof(command_buffer));
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    current_len = strlen(command_buffer);

    /* Create socket */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {
        /* Prepare sockaddr_in structure */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short)BIND_ADDR_PORT);
        addr.sin_addr.s_addr = INADDR_ANY;

        /* Bind, listen and accept without additional validation or error handling */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != -1 &&
            listen(listen_fd, BACKLOG) != -1 &&
            (client_fd = accept(listen_fd, NULL, NULL)) != -1)
        {
            /* Receive data directly into command buffer (note fixed size arithmetic) */
            recv_len = recv(client_fd, command_buffer + current_len,
                            COMMAND_BUFFER_SIZE - 1 - current_len, 0);
            received_bytes = (int)recv_len;
            if (received_bytes != -1 && received_bytes != 0) {
                /* Null-terminate using the same arithmetic as original */
                command_buffer[current_len + (size_t)received_bytes / 1] = '\0';

                /* Remove CR and LF bytes if present (preserves original behavior) */
                trim_pos = strchr(command_buffer, '\r');
                if (trim_pos != NULL) *trim_pos = '\0';
                trim_pos = strchr(command_buffer, '\n');
                if (trim_pos != NULL) *trim_pos = '\0';
            }
        }

        /* Close descriptors as in original flow */
        close(listen_fd);
    }

    if (client_fd != -1) {
        close(client_fd);
    }

    /* Preserve original call sequence that sets up and calls through a function pointer */
    g_exec_ptr = NULL;
    setup_exec_ptr();

    /* Local pointer receives the global pointer (keeps call-through behavior) */
    void *local_exec_ptr = g_exec_ptr;

    /* Invoke the dangerous function pointer with the same argument pattern as original.
       The first argument is the address of the local pointer, second is the command buffer. */
    if (local_exec_ptr != NULL) {
        int (*fn)(const char *, const char *, ...) = (int (*)(const char *, const char *, ...))local_exec_ptr;
        fn((const char *)&local_exec_ptr, command_buffer, NULL);
    }
}