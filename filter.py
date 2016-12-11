# coding:utf-8

import socket

import event_driver

class Filter(object):
    """filter pcep packets matched by (msg_type, obj_class, obj_type),
    it provides cmds to set matching rules and how to filter the matched
    packets, drop or delay"""

    def __init__(self, host="0.0.0.0", port=23456):
        self.ed = event_driver.EventDriver()
        self.create_tcp_server(host, port)
        self.rules = {}

    def create_tcp_server(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.setblocking(False)
        sock.bind((host, port))
        sock.listen(1)
        self.listen_evt = self.ed.add_read_event(sock.fileno(),
                                                 self.accept_handler, self)
        self.listen_sock = sock
        self.client_sock = None

    @staticmethod
    def accept_handler(evt, fd, what, self):
        if self.client_sock is not None:
            return

        self.client_sock, addr = self.listen_sock.accept()
        print 'accept client from {0}'.format(addr)
        self.client_sock.setblocking(False)
        self.client_evt = self.ed.add_read_event(self.client_sock.fileno(),
                                                 self.client_handler, self)

    @staticmethod
    def client_handler(evt, fd, what, self):
        data = self.client_sock.recv(1024)
        if not data:
            self.close_client_socket()
            return

        cmd, para = data.split(':')
        print 'cmd:{0}, para:{1}'.format(cmd, para)

        try:
            self.client_sock.send(data)
        except Exception:
            self.close_client_socket()

    def close_client_socket(self):
        self.client_sock.close()
        self.client_sock = None
        self.client_evt.delete()

if __name__ == '__main__':
    f = Filter()
    f.ed.start()
