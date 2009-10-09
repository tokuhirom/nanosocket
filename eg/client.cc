#include "../nanosocket.h"
#include "../extlib/nanotap.h"
#include <assert.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    assert(argc == 2);
    const char * msg = "hello\n";

    nanosocket::Socket sock;
    ok(sock.socket(AF_INET, SOCK_STREAM));
    ok(sock.connect("localhost", atoi(argv[1])), "connect");
    sock.send(msg, strlen(msg));
    char buf[1024];
    int received = sock.recv(buf, sizeof(buf));
    is((int)received, (int)strlen(msg), "response length");
    is(std::string(buf, received), std::string(msg), "received message");
    sock.close();

    done_testing();
}

