import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
import logging
from utils import get_random_string, AESCipher

class Client:
    """General purpose client usable with the provided server class.
    It support RSA and AES encryption depending on the server parameter.
    """
    def __init__(self, ip="127.0.0.1", key=None, port=1233, logger=None, auto_encrypt=False):
        """Creator of the class

        Args:
            ip (str, optional): Server ip address. Defaults to "127.0.0.1".
            key (rsa export, optional): RSA key in order to intialize the AES, if not provided they are generated Automaticaly. Defaults to None.
            port (int, optional): Server port. Defaults to 1233.
            logger (logger, optional): Optionnal Logger object overiding created ones. Defaults to None.
            auto_encrypt (bool, optional): Automaticaly generate RSA and AES encrypted channel. Defaults to False.
        """
        self.__host = ip
        self.__port = port
        if auto_encrypt:
            RSAkey = RSA.generate(1024)
            k = RSAkey.exportKey("PEM")
            p = RSAkey.publickey().exportKey("PEM")
            key = [k, p]

        if key is not None:

            if type(key) == list:
                self.__my_private = key[0]
                self.__my_public = key[1]
            else:
                self.__my_private = key
                self.__my_public = None

            self.__decryptor = PKCS1_OAEP.new(RSA.import_key(self.__private))
        else:

            self.__my_private = None
            self.__my_public = None
            self.__decryptor = None

        self._is_encrypted = False

        self.socket = socket.socket()
        self.__encryptor = None

        self._logger = logger
        if logger is None:
            self.setup_default_logger()

    def __force_auto_encrypt(self):

        RSAkey = RSA.generate(1024)
        k = RSAkey.exportKey("PEM")
        p = RSAkey.publickey().exportKey("PEM")
        key = [k, p]

        if key is not None:

            if type(key) == list:
                self.__my_private = key[0]
                self.__my_public = key[1]
            else:
                self.__my_private = key
                self.__my_public = None

            self.__decryptor = PKCS1_OAEP.new(RSA.import_key(self.__my_private))
        else:

            self.__my_private = None
            self.__my_public = None
            self.__decryptor = None


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
        """Connect to the server

        Returns:
            int: Error code if so
        """
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

        if self._is_encrypted:
            if self.__my_private == None:
                self.__force_auto_encrypt()
            protocol_message = json.dumps({"encryption": 1, "public_key": self.__my_public.decode('utf-8')})
            self.socket.send(str.encode(protocol_message) + b"\0")
        else:
            protocol_message = json.dumps({"encryption": 0, "public_key": ""})
            self.socket.send(str.encode(protocol_message) + b"\0")

        # Establishing AES channel
            
            
            
        AES_protocol_message = self.socket.recv(1024)[:-1]
        data = self.__decryptor.decrypt(AES_protocol_message).decode("utf-8")
        data = json.loads(data)
        AES_key = data["AES_key"]
        self.AES_manager = AESCipher(AES_key)
        self._logger.debug(f"Received message :  'AES_Key_Hidden'")

    def send(self, message):
        """Send the provided message to the server

        Args:
            message (str): Message to be sent to the server.
        """
        self._logger.info(f"Sending message : {message}")
        
        if self._is_encrypted:
            n = 24
            message += "\1"
            chunks = [message[i:i+n] for i in range(0, len(message), n)]
            for chunk in chunks:
                encrypted = self.AES_manager.encrypt(chunk)
                self.socket.send(encrypted + b"\0")
        else:
            self.socket.send(bytes(message, "utf-8") + b"\0")

    def receive(self):
        """Receive a message from the server

        Returns:
            string: Message from the server (usualy json string ready to be loaded)
        """
        stop = False
        if self._is_encrypted:
            data = ""
            while not data.endswith("\1"):
                encoded_data = b""
                while not encoded_data.endswith(b"\0"):
                    recv_data = self.socket.recv(2048)

                    encoded_data = encoded_data + recv_data
                    if not recv_data:
                        stop = True
                        break
                if stop:
                    return 0
                
                encoded_data = encoded_data[:-1]
                data += self.AES_manager.decrypt(encoded_data)
            data = data[:-1]
            self._logger.info(f"Received message : {data}")
        
        else:
            data = b""
            while not data.endswith(b"\0"):
                recv_data = self.socket.recv(2048)

                data = data + recv_data
                if not recv_data:
                    stop = True
                    break
            if stop:
                return 0
            
            data = data[:-1]
            data = data.decode('utf-8')
            self._logger.info(f"Received message : {data}")

        return data

    def disconnect(self):
        """Disconnect from the server.
        """
        self._logger.info(f"Connection with {self.__host}:{self.__port} closed")
        self.socket.close()

    def __del__(self):
        self.disconnect()


if __name__ == "__main__":

    myClient = Client()
    myClient.connect()
    while True:
        message = input("To send: ")
        data = {}
        myClient.send(message)

        response = myClient.receive()
        print(response)

        if message == "close":
            break

c = Client()