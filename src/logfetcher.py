#!/usr/bin/env python

__author__ = "benj.renard@gmail.com"

import zmq

import logging
import re
import sys
import threading

import pdb

from zmq.eventloop import ioloop, zmqstream

from swabber_interface import SwabberConn
from simple_live_sniffer import SimpleLiveSniffer

#BINDSTRING = "tcp://127.0.0.1:22621"
# TODO: change port to botbanger's ??
BINDSTRING = "tcp://127.0.0.1:22621"

BOTBANGER_LOG = "botbanger_log"


class LogFetcher(threading.Thread):

    def __init__(self, bindstring, verbose=False):
        self._swabber_interface = SwabberConn("127.0.0.1", 22622)
        self._live_sniffer = SimpleLiveSniffer()

        #we need to load the models
        model_list = open("conf/botbanger.conf")
        for cur_model_file in model_list:
            cur_model_file = cur_model_file.strip('\n') 
            if cur_model_file: #ignore empty lines
                with open("conf/"+cur_model_file) as cur_model:
                    self._live_sniffer.addFailModel(cur_model.read())

        context = zmq.Context()
        self.socket = context.socket(zmq.SUB)
        subscriber = zmqstream.ZMQStream(self.socket)
        self.socket.setsockopt(zmq.SUBSCRIBE, BOTBANGER_LOG)
        self.socket.connect(BINDSTRING)
        threading.Thread.__init__(self)
        subscriber.on_recv(self.subscription)

    # def __init__(self, bindstring, verbose=False):
    #     self.bindstring = bindstring

    #     self._swabber_interface = SwabberConn
    #     self._live_sniffer = SimpleLiveSniffer

    #     context = zmq.Context()
    #     self.socket = context.socket(zmq.SUB)
    #     subscriber = zmqstream.ZMQStream(self.socket)
    #     self.socket.setsockopt(zmq.SUBSCRIBE, BOTBANGER_LOG)
    #     self.socket.connect(bindstring)

    #     threading.Thread.__init__(self)

    #     subscriber.on_recv(self.subscription)

    def subscription(self, message):
        action, ipaddress = message[0:2]

        ipaddress = ipaddress.strip()
        ipmatch = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if not ipmatch.match(ipaddress):
            logging.error("Failed to validate IP address %s - rejecting", ipaddress)
            return False
        
        #pdb.set_trace()
        if action == BOTBANGER_LOG:

            logging.debug("Received log for ip = %s", message[1])
            logging.debug("log is: %s", message)

            cur_log_rec = {}
            cur_log_rec["host"] = message[1]
            cur_log_rec["time"] = message[2]
            cur_log_rec["request"] = message[3]
            cur_log_rec["type"] = message[4]
            cur_log_rec["status"] = message[5]
            cur_log_rec["size"] = (not message[6]) and '0' or message[6]
            cur_log_rec["agent"] = message[7]
            cur_log_rec["hit"] = message[8]

            # check if we have a bot and ban it if necessary
            self.ban_if_bot(cur_log_rec)

        else:
            logging.error("Got an invalid message header: %s", message)

    def ban_if_bot(self, log_rec):
        if (self._live_sniffer.is_this_a_bot(log_rec)):
            logging.info("log record from a bot %s", log_rec)
            self._swabber_interface.ban(log_rec["host"])
        else:
            logging.info("%s doesn't seem to be a bot", log_rec["host"])

    def stopIt(self):
        self.loop.stop()

    def run(self):
        self.loop = ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    verbose = True

    mainlogger = logging.getLogger()
    logging.basicConfig(level=logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    mainlogger.addHandler(ch)

    lfetcher = LogFetcher(BINDSTRING, verbose)
    lfetcher.run()
