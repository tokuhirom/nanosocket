#include "../nanosocket.h"
#include "../extlib/nanotap.h"
#include <stdlib.h>
#include <assert.h>

int main(int argc, char **argv) {
    assert(argc == 2);

    nanosocket::Socket sock;
    assert(sock.socket(AF_INET, SOCK_STREAM));
    assert(sock.bind_inet("127.0.0.1", atoi(argv[1])));
    assert(sock.listen());

    while (1) {
        nanosocket::Socket csock(sock.accept());
        if (!csock) { break; }

        char buf[1024];
        while (1) {
            int received = csock.recv(buf, sizeof(buf));
            if (received < 0) { printf("%s\n", csock.errstr().c_str()); }
            if (received <= 0) { break; }
            csock.send(buf, received);
        }
        csock.close();
    }
    sock.close();

    done_testing();
}

