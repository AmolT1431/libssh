#include <libssh/libssh.h>
#include <libssh/server.h>
#include <iostream>
#include <cstring>
#include <cstdlib>

int main() {
    ssh_bind sshbind = ssh_bind_new();
    if (sshbind == nullptr) {
        std::cerr << "Failed to create ssh_bind\n";
        return EXIT_FAILURE;
    }

    // SSH server options
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "2222");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "F:/work/libssh/ssh_host_rsa_key");

    if (ssh_bind_listen(sshbind) < 0) {
        std::cerr << "Error listening: " << ssh_get_error(sshbind) << "\n";
        ssh_bind_free(sshbind);
        return EXIT_FAILURE;
    }

    std::cout << "SSH server listening on port 2222...\n";

    ssh_session session = ssh_new();
    if (session == nullptr) {
        std::cerr << "Failed to create ssh session\n";
        ssh_bind_free(sshbind);
        return EXIT_FAILURE;
    }

    if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
        std::cerr << "Error accepting connection: " << ssh_get_error(sshbind) << "\n";
        ssh_free(session);
        ssh_bind_free(sshbind);
        return EXIT_FAILURE;
    }
    std::cout << "Client connected!\n";

    if (ssh_handle_key_exchange(session)) {
        std::cerr << "Key exchange failed: " << ssh_get_error(session) << "\n";
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        return EXIT_FAILURE;
    }

    // Authentication loop
    ssh_message message;
    bool authenticated = false;

    while ((message = ssh_message_get(session)) != nullptr) {
        if (ssh_message_type(message) == SSH_REQUEST_AUTH &&
            ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {

            const char *username = ssh_message_auth_user(message);
            const char *password = ssh_message_auth_password(message);

            std::cout << "Username: " << username << ", Password: " << password << "\n";

            if (strcmp(username, "user") == 0 && strcmp(password, "1234") == 0) {
                ssh_message_auth_reply_success(message, 0);
                authenticated = true;
                ssh_message_free(message);
                break;
            } else {
                ssh_message_reply_default(message);
            }
        } else {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    if (!authenticated) {
        std::cerr << "Authentication failed!\n";
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        return EXIT_FAILURE;
    }

    std::cout << "Client authenticated successfully!\n";

    // Wait for a channel request
    ssh_channel channel = nullptr;
    while ((message = ssh_message_get(session)) != nullptr) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {

            channel = ssh_message_channel_request_open_reply_accept(message);
            ssh_message_free(message);
            break;
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    if (channel == nullptr) {
        std::cerr << "Failed to open channel\n";
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        return EXIT_FAILURE;
    }

    // Wait for shell request
    while ((message = ssh_message_get(session)) != nullptr) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL &&
            ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
            ssh_message_channel_request_reply_success(message);
            ssh_message_free(message);
            break;
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    std::cout << "Shell opened. Sending welcome message...\n";

    ssh_channel_write(channel, "Welcome to the fake SSH server!\nType something and it will echo back.\n", 72);

    char buffer[256];
    int nbytes;
    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
        ssh_channel_write(channel, buffer, nbytes); // Echo back
    }

    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);

    return EXIT_SUCCESS;
}
