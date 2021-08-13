import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
import logging


class Client:
    def __init__(self, ip="127.0.0.1", key=None, port=1233, logger=None):
        self.__host = ip
        self.__port = port
        self._is_encrypted = False
        self.__public_key = None
        self.socket = socket.socket()
        self.__encryptor = None

        self._logger = logger
        if logger is None:
            self.setup_default_logger()

    def setup_default_logger(self):
        logger = logging.getLogger("client")
        if logger.hasHandlers():
            logger.handlers.clear()
        logger.setLevel(logging.INFO)

        fh = logging.FileHandler("client.log")
        fh.setLevel(logging.INFO)

        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)

        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh.setFormatter(formatter)
        sh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(sh)
        self._logger = logger

    def connect(self):
        try:
            self.socket.connect((self.__host, self.__port))
        except socket.error as e:
            self._logger.error(str(e))
            return 0

        self._logger.info(f"Connected to {self.__host}:{self.__port}")

        protocol_message = self.socket.recv(1024)[:-1].decode("utf-8")
        self._logger.info(f"Received protocol message : {protocol_message}")
        protocol_dict = json.loads(protocol_message)

        try:
            if protocol_dict["encryption"] == 1:
                self.__public_key = protocol_dict["public_key"]
        except KeyError:
            pass

        if self.__public_key is not None:
            self.__encryptor = PKCS1_OAEP.new(RSA.import_key(self.__public_key))
            self._is_encrypted = True
        else:
            self._is_encrypted = False

    def send(self, message):
        self._logger.info(f"Sending message : {message}")
        if self._is_encrypted:
            encrypted = self.__encryptor.encrypt(bytes(message, "utf-8"))
            self.socket.send(encrypted + b"\0")
        else:
            self.socket.send(bytes(message, "utf-8") + b"\0")

    def receive(self):

        Response = self.socket.recv(1024)
        message = Response.decode("utf-8")
        self._logger.info(f"Received message : {message}")
        return message

    def disconnect(self):
        self._logger.info(f"Connection with {self.__host}:{self.__port} closed")
        self.socket.close()

    def __del__(self):
        self.disconnect()


if __name__ == "__main_":

    myClient = Client()
    myClient.connect()
    while True:
        message = input("To send: ")
        myClient.send(message)

        response = myClient.receive()
        print(response)

        if message == "close":
            break