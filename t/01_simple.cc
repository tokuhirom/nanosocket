#include "../nanosocket.h"
#include "../extlib/nanotap.h"

int main() {
    nanosocket::TCPSocket sock;
    ok(sock.connect("mixi.jp", 80), "connect");
    sock.write("GET / HTTP/1.0\r\n\r\n", sizeof("GET / HTTP/1.0\r\n\r\n")-1);
    char buf[1024];
    ok(sock.read(buf, sizeof(buf)), "read");
    string_contains(buf, "HTTP/1.1 200 OK", "content");
    sock.close();
    done_testing();
}

