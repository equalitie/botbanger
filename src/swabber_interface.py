import zmq
from zmq.eventloop import zmqstream

class SwabberConn(object):
    def __init__(self, swabber_server, swabber_port):
        self.swabber_server = swabber_server
        self.swabber_port = swabber_port
        context   = zmq.Context(1)
        socket    = context.socket(zmq.PUB)
        publisher = zmqstream.ZMQStream(socket)
        socket.bind("tcp://%s:%d" % (swabber_server, swabber_port))
        self.socket = socket
        self.publisher = publisher

    def ban(self, ip_to_ban):
        self.publisher.send_multipart(("swabber_bans", ip_to_ban))

