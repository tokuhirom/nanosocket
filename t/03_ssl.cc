#include "../nanosocket.h"
#include "../extlib/nanotap.h"
#include <assert.h>

int main() {
    nanosocket::SSLSocket sock;
    ok(sock.connect("wassr.jp", 443), "connect");
    sock.send("GET /contact/us HTTP/1.0\r\nHost: wassr.jp\r\n\r\n", sizeof("GET /contact/us HTTP/1.0\r\nHost: wassr.jp\r\n\r\n")-1);
    char buf[1024*1024];
    int received = sock.recv(buf, sizeof(buf));
    assert(received > 0);
    buf[received] = '\0';
    string_contains(buf, "sledge_sid", "valid content");
    done_testing();
}

