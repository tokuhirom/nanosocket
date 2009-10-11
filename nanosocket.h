/*
 * Copyright (c) 2009, tokuhiro matsuno
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * * Neither the name of the <ORGANIZATION> nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef NANOSOCKET_H_
#define NANOSOCKET_H_

#ifdef HAVE_SSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <string>
#include <cstring>

namespace nanosocket {
    /**
     * The abstraction class of TCP Socket.
     */
    class Socket {
    protected:
        std::string errstr_;
        int fd_;
    public:
        Socket() {
            fd_ = -1;
        }
        Socket(int fd) {
            fd_ = fd;
        }
        ~Socket() {
            if (fd_ != -1) { this->close(); }
        }
        Socket(const Socket &sock) {
            this->fd_ = sock.fd_;
        }
        bool socket(int domain, int type) {
            if ((fd_ = ::socket(domain, type, 0)) >= 0) {
                return true;
            } else {
                errstr_ = strerror(errno);
                return false;
            }
        }
        /**
         * connect socket to the server.
         * @return true if success to connect.
         */
        bool connect(const char *host, short port) {
            // open socket as tcp/inet by default.
            if (fd_ == -1) {
                if (!this->socket(AF_INET, SOCK_STREAM)) {
                    return false;
                }
            }

            struct hostent * servhost = gethostbyname(host);
            if (!servhost) {
                errstr_ = std::string("error in gethostbyname: ") + host;
                return false;
            }

            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons( port );
            memcpy(&addr.sin_addr, servhost->h_addr, servhost->h_length);

            if (::connect(fd_, (struct sockaddr *)&addr, sizeof(addr)) == -1){
                errstr_ = strerror(errno);
                return false;
            }

            return true;
        }
        int send(const char *buf, size_t siz) {
            return ::send(fd_, buf, siz, 0);
        }
        int recv(char *buf, size_t siz) {
            int received = ::read(fd_, buf, siz);
            if (received < 0) {
                errstr_ = strerror(errno);
            }
            return received;
        }
        int close() {
            return ::close(fd_);
        }
        int setsockopt(int level, int optname,
                              const void *optval, socklen_t optlen) {
            return ::setsockopt(fd_, level, optname, optval, optlen);
        }
        int getsockopt(int level, int optname,
                              const void *optval, socklen_t optlen) {
            return ::setsockopt(fd_, level, optname, optval, optlen);
        }
        /**
         * return latest error message.
         */
        std::string errstr() { return errstr_; }
        int fd() { return fd_; }
        int fileno() { return fd_; }
#ifdef AF_UNIX
        bool bind_unix(const std::string &path) {
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(struct sockaddr_un)); // clear
            if ((unsigned int)path.length() >= sizeof(addr.sun_path)) {
                errstr_ = "socket path too long";
                return false;
            }
            addr.sun_family = AF_UNIX;
            memcpy(addr.sun_path, path.c_str(), path.length());
            addr.sun_path[path.length()] = '\0';
            socklen_t len = path.length() + (sizeof(addr) - sizeof(addr.sun_path));
            return this->bind((const sockaddr*)&addr, len);
        }
#endif
#if defined(AF_INET6)
        bool bind_inet6(const char *host, short port) {
            struct sockaddr_in6 addr;
            memset(&addr, 0, sizeof(sockaddr_in6)); // clear
            addr.sin6_family = AF_INET6;
            int pton_ret = inet_pton(AF_INET6, host, addr.sin6_addr.s6_addr);
            if (pton_ret == 0) {
                errstr_ = "invalid ip form";
                return false;
            } else if (pton_ret == -1) {
                errstr_ = "unknown protocol family";
                return false;
            }
            addr.sin6_port = htons(port);
            return this->bind((const sockaddr*)&addr, sizeof(sockaddr_in6));
        }
#endif
        bool bind_inet(const char *host, short port) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            in_addr_t hostinfo = inet_addr(host);
            if (hostinfo == INADDR_NONE) {
                errstr_ = "invalid ip";
                return false;
            }
            addr.sin_port = htons((short)port);
            // addr.sin_addr.s_addr = hostinfo;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            return this->bind((const struct sockaddr*)&addr, sizeof(sockaddr_in));
        }
        bool bind(const struct sockaddr *addr, socklen_t len) {
            if (::bind(fd_, addr, len) == 0) {
                return true;
            } else {
                errstr_ = strerror(errno);
                return false;
            }
        }
        bool listen() {
            return this->listen(SOMAXCONN);
        }
        bool listen(int backlog) {
            if (::listen(fd_, backlog) == 0) {
                return true;
            } else {
                errstr_ = strerror(errno);
                return false;
            }
        }
        bool getpeername(struct sockaddr *name, socklen_t *namelen) {
            if (::getpeername(fd_, name, namelen) == 0) {
                return true;
            } else {
                errstr_ = strerror(errno);
                return false;
            }
        }
        bool getsockname(struct sockaddr *name, socklen_t *namelen) {
            if (::getsockname(fd_, name, namelen) == 0) {
                return true;
            } else {
                errstr_ = strerror(errno);
                return false;
            }
        }
        /// shortcut
        int accept() {
            return this->accept(NULL, NULL);
        }
        int accept(struct sockaddr *addr, socklen_t *addrlen) {
            int newfd;
            if ((newfd = ::accept(fd_, addr, addrlen)) >= 0) {
                return newfd;
            } else {
                errstr_ = strerror(errno);
                return -1;
            }
        }
        operator bool() const {
            return fd_ != -1;
        }
    };

#ifdef HAVE_SSL
    class SSLSocket:Socket {
    private:
        ::SSL *ssl_;
        ::SSL_CTX *ctx_;
    public:
        bool connect(const char *host, short port) {
            if (Socket::connect(host, port)) {
                SSL_load_error_strings();
                SSL_library_init();
                ctx_ = SSL_CTX_new(SSLv23_client_method());
                if ( ctx_ == NULL ){
                    ERR_print_errors_fp(stderr);
                    return false;
                }
                ssl_ = SSL_new(ctx_);
                if ( ssl_ == NULL ){
                    ERR_print_errors_fp(stderr);
                    return false;
                }
                if ( SSL_set_fd(ssl_, fd_) == 0 ){
                    ERR_print_errors_fp(stderr);
                    return false;
                }
                RAND_poll();
                if (RAND_status() == 0) {
                    errstr_ = "bad random generator";
                    return false;
                }
                if ( SSL_connect(ssl_) != 1 ){
                    ERR_print_errors_fp(stderr);
                    return false;
                }
                return true;
            } else {
                return false;
            }
        }
        int send(const char *buf, size_t siz) {
            return SSL_write(ssl_, buf, siz);
        }
        int recv(char *buf, size_t siz) {
            int received = ::SSL_read(ssl_, buf, siz);
            if (received < 0) {
                errstr_ = strerror(errno);
            }
            return received;
        }
        int close() {
            if ( SSL_shutdown(ssl_) != 1 ){
                ERR_print_errors_fp(stderr);
                exit(1);
            }
            ::close(fd_);
            fd_ = -1;

            SSL_free(ssl_); 
            SSL_CTX_free(ctx_);
            ERR_free_strings();
        }
    };
#endif
}

#endif // NANOSOCKET_H_

