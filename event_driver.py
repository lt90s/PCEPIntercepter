# coding: utf-8

import libevent

class EventDriver(object):
    __base__ = libevent.Base()

    def __init__(self):
        pass

    def add_read_event(self, fd, cb, ud, timeout=-1):
        """fd must be in non-blocking mode.
        the returned value must be kept referenced if you want
        to recieve the readable event
        """
        evt = libevent.Event(self.__base__, fd,
                             libevent.EV_READ|libevent.EV_PERSIST,
                             cb, ud)
        evt.add(timeout)
        return evt

    def add_timer(self, cb, ud, timeout, oneshot=False):
        timer = libevent.Timer(self.__base__, self.fire_timer,
                               (oneshot, timeout, cb, ud))
        timer.add(timeout)
        return timer

    def add_oneshort_timer(self, cb, ud, timeout):
        return self.add_timer(cb, ud, timeout, True)

    @staticmethod
    def fire_timer(timer, ud_tup):
        oneshot, timeout, cb, ud = ud_tup
        cb(timer, ud)
        if not oneshot:
            timer.add(timeout)

    def start(self):
        self.__base__.loop()

if __name__ == '__main__':
    ed = EventDriver()
    def timer_func(timer, ud):
        print 'timer_func'

    def oneshot_timer_func(timer, ud):
        print 'oneshot_timer_func'
    timer = ed.add_timer(timer_func, None, 5)
    oneshot_timer = ed.add_oneshort_timer(oneshot_timer_func, None, 10)
    ed.start()
