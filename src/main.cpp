#include <libssh/libssh.h>
#include <libssh/server.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define USERNAME "at"
#define PASSWORD "123"
#define PORT "2222"
#define RSA_KEY_PATH "C:/Users/AT/Desktop/libossh/libssh/ssh_host_rsa_key"

int authenticate_password(ssh_session session) {
    ssh_message message;

    while ((message = ssh_message_get(session)) != NULL) {
        if (ssh_message_type(message) == SSH_REQUEST_AUTH &&
            ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
            const char* user = ssh_message_auth_user(message);
            const char* pass = ssh_message_auth_password(message);

            if (strcmp(user, USERNAME) == 0 && strcmp(pass, PASSWORD) == 0) {
                ssh_message_auth_reply_success(message, 0);
                ssh_message_free(message);
                return 1;
            } else {
                ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
                ssh_message_reply_default(message);
            }
        } else {
            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    return 0;
}

void run_shell(ssh_channel channel) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hInRead, hInWrite;
    HANDLE hOutRead, hOutWrite;

    CreatePipe(&hInRead, &hInWrite, &sa, 0);
    CreatePipe(&hOutRead, &hOutWrite, &sa, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = hInRead;
    si.hStdOutput = hOutWrite;
    si.hStdError = hOutWrite;

    BOOL success = CreateProcessA(
        NULL,
        (LPSTR)"cmd.exe",
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        ssh_channel_write(channel, "Failed to launch cmd.exe\r\n", 28);
        return;
    }

    // Close unused handles
    CloseHandle(hInRead);
    CloseHandle(hOutWrite);

    char buffer[256];
    DWORD bytesRead, bytesWritten;

    while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
        // Read from process stdout
        if (PeekNamedPipe(hOutRead, NULL, 0, NULL, &bytesRead, NULL) && bytesRead > 0) {
            ReadFile(hOutRead, buffer, sizeof(buffer), &bytesRead, NULL);
            ssh_channel_write(channel, buffer, bytesRead);
        }

        // Read from SSH client
        int rc = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
        if (rc > 0) {
            WriteFile(hInWrite, buffer, rc, &bytesWritten, NULL);
        }

        Sleep(50);
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(hInWrite);
    CloseHandle(hOutRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
}

int main() {
    ssh_bind sshbind = ssh_bind_new();
    ssh_session session = ssh_new();
    ssh_channel channel = NULL;
    ssh_message message;

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, PORT);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, RSA_KEY_PATH);

    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "Error listening: %s\n", ssh_get_error(sshbind));
        return -1;
    }

    printf("Listening on port %s...\n", PORT);

    if (ssh_bind_accept(sshbind, session) != SSH_OK) {
        fprintf(stderr, "Error accepting session: %s\n", ssh_get_error(sshbind));
        return -1;
    }

    if (ssh_handle_key_exchange(session)) {
        fprintf(stderr, "Key exchange error: %s\n", ssh_get_error(session));
        return -1;
    }

    if (!authenticate_password(session)) {
        fprintf(stderr, "Authentication failed.\n");
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    while ((message = ssh_message_get(session)) != NULL) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            channel = ssh_message_channel_request_open_reply_accept(message);
            ssh_message_free(message);
            break;
        } else {
            ssh_message_reply_default(message);
            ssh_message_free(message);
        }
    }

    if (!channel) {
        fprintf(stderr, "No session channel\n");
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    // Handle PTY request
    while ((message = ssh_message_get(session)) != NULL) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL &&
            ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) {
            ssh_message_channel_request_reply_success(message);
        } else if (ssh_message_type(message) == SSH_REQUEST_CHANNEL &&
                   ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
            ssh_message_channel_request_reply_success(message);
            ssh_message_free(message);
            break;
        } else {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    run_shell(channel);

    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);
    ssh_finalize();

    return 0;
}
