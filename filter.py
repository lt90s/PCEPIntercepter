# coding:utf-8

import socket
import logging
import struct
from scapy.utils import hexdump

import event_driver

logger = logging.getLogger(__name__)

class Filter(object):
    """filter pcep packets matched by (nodeid, msg_type, obj_class, obj_type, offset, length, value),
    it provides cmds to set matching rules and how to filter the matched
    packets, drop or delay"""

    DROP = 0
    ACCEPT = 1
    DELAY = 2

    ACTION_S = ("DROP", "ACCEPT", "DELAY")

    CMD_HELP = [
                "drop:node_id, msg_type, obj_class, obj_type, offset, length, value\n",
                "accept:node_id, msg_type, obj_class, obj_type, offset, length, value\n",
                "delay:node_id, msg_type, obj_class, obj_type, offset, length, value, delay_second\n",
                ]

    def __init__(self, host="0.0.0.0", port=23456):
        self.ed = event_driver.EventDriver()
        self.create_tcp_server(host, port)
        self.rules = {}

    def create_tcp_server(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        sock.bind((host, port))
        sock.listen(1)
        self.listen_evt = self.ed.add_read_event(sock.fileno(),
                                                 self.accept_handler, self)
        self.listen_sock = sock
        self.client_sock = None
        self.delayed_pkts = {}

    @staticmethod
    def accept_handler(evt, fd, what, self):
        if self.client_sock is not None:
            return

        self.client_sock, addr = self.listen_sock.accept()
        logger.debug('accept client from {0}'.format(addr))
        self.client_sock.setblocking(False)
        self.client_evt = self.ed.add_read_event(self.client_sock.fileno(),
                                                 self.client_handler, self)

    @staticmethod
    def client_handler(evt, fd, what, self):
        # exception happens when read            +        data = self.client_sock.recv(1024)
        try:
            data = self.client_sock.recv(1024)
        except Exception:
            self.close_client_socket()
            return

        if not data:
            self.close_client_socket()
            return

        data = self.process_cmd(data.strip())

        try:
            self.client_sock.send(data)
        except Exception:
            self.close_client_socket()

    def close_client_socket(self):
        self.client_sock.close()
        self.client_sock = None
        self.client_evt.delete()

    def process_delay(self, para):
        try:
            nodeid = para[0].strip()
            msg_type, obj_class, obj_type, offset, length, value, timeout = \
                    (int(x.strip()) for x in para[1:])
            if length not in (0,1,2,4):
                raise ValueError("")
        except Exception:
            return self.CMD_HELP[self.DELAY]

        rule = (nodeid, msg_type, obj_class, obj_type)

        if not self.rules.has_key(rule) and timeout == 0:
            return

        if not self.rules.has_key(rule):
            self.rules[rule] = [self.DELAY, 0, {}]

        if timeout != 0:
            self.rules[rule][2][offset] = (length, value, timeout)
        elif self.rules[rule][2][offset]:
            del self.rules[rule][2][offset]
            if len(self.rules[rule][2]) == 0:
                del self.rules[rule]
        logger.debug("Add rule: {0} {1} {2} {3} {4}=> DELAY".format(rule, offset, length, value, timeout))
        return "Success\n"

    def process_drop_accept(self, cmd, para):
        try:
            nodeid = para[0].strip()
            msg_type, obj_class, obj_type, offset, length, value = \
                    (int(x.strip()) for x in para[1:])
            if length not in (0,1,2,4):
                raise ValueError("")
        except Exception:
            if cmd == "drop":
                return self.CMD_HELP[self.DROP]
            else:
                return self.CMD_HELP[self.ACCEPT]

        rule = (nodeid, msg_type, obj_class, obj_type)

        if cmd == "drop":
            if not self.rules.has_key(rule):
                self.rules[rule] = [self.DROP, 0, {}]
            self.rules[rule][2][offset] = (length, value)
            logger.debug("Add rule: {0} {1} {2} {3}=> DROP".format(rule, offset, length, value))
        else:
            if self.rules.has_key(rule) and self.rules[rule][2].has_key(offset):
                del self.rules[rule][2][offset]
                if len(self.rules[rule][2]) == 0:
                    del self.rules[rule]

            logger.debug("Add rule: {0} => ACCEPT".format(rule))

        return "Success\n"

    def process_show_rules_cmd(self):
        s = ""
        for k, v in self.rules.items():
            s += "Rule: {0} => {1}\n".format(k, self.ACTION_S[v[0]])
            for kk, vv in v[2].items():
                s += "\toffset: {0} length: {1} value: {2}\n".format(kk, vv[0], vv[1])
        return s


    def process_cmd(self, cmd):
        logger.debug(cmd)
        try:
            cmd, para = cmd.split(':')
        except Exception:
            return ''.join(self.CMD_HELP)

        logger.debug('cmd:{0}, para:{1}'.format(cmd, para))
        cmd = cmd.strip()
        para = para.split(',')
        if cmd in [ "drop", "accept" ]:
            return self.process_drop_accept(cmd, para)
        elif cmd == "delay":
            return self.process_delay(para)
        elif cmd == "show-rules":
            return self.process_show_rules_cmd()
        else:
            return ''.join(self.CMD_HELP)

        return "Success\n"

    def add_delay_packet(self, delay, pkt, rule):
        timer = self.ed.add_oneshot_timer(self.accept_delayed_packet, self, delay)
        self.delayed_pkts[(timer,)] = (pkt, rule)

    @staticmethod
    def accept_delayed_packet(timer, self):
        pkt, rule = self.delayed_pkts[(timer,)]
        pkt.accept()
        logger.debug("accept delayed packet: {0}".format(rule))
        del self.delayed_pkts[(timer,)]

    def match_rule(self, rule_key, raw_pcep):
        rule = self.rules[rule_key]
        for offset, lv in rule[2].items():
            self.offset = offset
            if offset == 0:
                return True

            length, value = lv
            if offset + length > len(raw_pcep):
                continue

            raw_value = raw_pcep[offset:offset+length]
            if length == 1:
                formatter = "!B"
            elif length == 2:
                formatter = "!H"
            elif length == 4:
                formatter == "!L"
            else:
                assert(false)
            raw_value = struct.unpack(formatter, raw_value)[0]
            logger.debug("matching : {0} {1} {2} {3} == {4}".format(rule_key,
                                            offset, length, value, raw_value))
            if value == raw_value:
                return True

        return False

    def do_filter(self, rule_key, raw_pcep, pkt):
        if rule_key not in self.rules or not self.match_rule(rule_key, raw_pcep):
            pkt.accept()
            logger.debug("Accept: {0}".format(rule_key))
            return
        hexdump(raw_pcep)
        rule = self.rules[rule_key]

        if rule[0] == self.DROP:
            logger.debug('Drop {0}'.format(rule_key))
            pkt.drop()
        elif rule[0] == self.DELAY:
            # set in match_rule
            offset = self.offset
            logger.debug('Delay {0} for {1}'.format(rule_key, rule[2][offset]))
            self.add_delay_packet(rule[2][offset][2], pkt, rule_key)
        else:
            logger.warn("Unknown action: {0}".format(rule[0]))



    def dump_rule(self):
        for rule, action in self.rules.items():
            logger.debug('{0} => {1}'.format(rule, action))

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
        format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
        datefmt='%a, %d %b %Y %H:%M:%S', filemode='w')
    f = Filter()
    f.ed.start()
