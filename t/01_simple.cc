#include "../nanosocket.h"
#include "../extlib/nanotap.h"

int main() {
    nanosocket::Socket sock;
    ok(sock.socket(AF_INET, SOCK_STREAM));
    ok(sock.connect("mixi.jp", 80), "connect");
    sock.send("GET / HTTP/1.0\r\n\r\n", sizeof("GET / HTTP/1.0\r\n\r\n")-1);
    char buf[1024];
    ok(sock.recv(buf, sizeof(buf)), "read");
    string_contains(buf, "HTTP/1.1 200 OK", "content");
    sock.close();
    done_testing();
}

