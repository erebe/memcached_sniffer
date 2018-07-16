#pragma once

#include <string>
#include <string_view>
#include <optional>

#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <resolv.h>
#include <errno.h>
#include <netinet/tcp.h>

#include <spdlog/spdlog.h>

namespace cnx {

static auto logger = spdlog::stdout_color_mt("sockets");

std::optional<int> connect_to(std::string_view host, int port) {

    // Create the socket
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        logger->error("Cannot create a TCP socket for {} -- {}", host, strerror(errno));
        return std::nullopt;
    }

    //Disable Nagle algorithm
    int nodelay = 1;
    socklen_t len = sizeof(nodelay);
    if(setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, len) < 0) {
        logger->error("Cannot disable Nagle algorithm -- {}", strerror(errno));
        return std::nullopt;
    }

    // Increase send buffer
    // Max payload for memcached is 1m so match it
    int size = 1024 * 1024 * 1;
    if(setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, len) < 0) {
        logger->error("Cannot increase send buffer of the socket -- {}", strerror(errno));
        return std::nullopt;
    }

    // Fill information regarding destination and connect
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(sockaddr_in));
    serv_addr.sin_port = htons(port);
    serv_addr.sin_family = AF_INET;
    inet_aton(host.data(), &serv_addr.sin_addr);
    if(connect(sock_fd, (sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
        logger->error("Cannot open remote connection to {}:{} -- {}", host, port, strerror(errno));
        return std::nullopt;
    } else {
        logger->info("Connected to {}:{}", host, port);
    }

    // Set the socket in non blocking mode
    int flags = fcntl(sock_fd, F_GETFL, 0);
    flags = fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);
    if(flags < 0) {
        logger->error("Cannot set socket as non blocking -- {}", strerror(errno));
        return std::nullopt;
    }

    // We are interested only by sending requests, we do not care of response
    // So close the read buffer it will avoid us syscalls to empty read buffer
    shutdown(sock_fd, SHUT_RD);

    return {sock_fd};
}


}
