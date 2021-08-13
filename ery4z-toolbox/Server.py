import socket
import os
from _thread import *
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import json


class Server:
    def __init__(self, routing, key=None, logger=None, host="127.0.0.1", port=1233, auto_encrypt=False):
        self.__host = host
        self.__port = port
        if auto_encrypt:
            RSAkey = RSA.generate(1024)
            k = RSAkey.exportKey("PEM")
            p = RSAkey.publickey().exportKey("PEM")
            key = [k, p]

        if key is not None:
            self._is_connection_encrypted = True
            if type(key) == list:
                self.__private = key[0]
                self.__public = key[1]
            else:
                self.__private = key
                self.__public = None

            self.__decryptor = PKCS1_OAEP.new(RSA.import_key(self.__private))
        else:
            self._is_connection_encrypted = False
            self.__private = None
            self.__public = None
            self.__decryptor = None

        self._route = routing
        self.__stop_server = False
        if logger is None:
            self.setup_default_logger()
        else:
            self._logger = logger

    def setup_default_logger(self):
        logger = logging.getLogger("server")
        if logger.hasHandlers():
            logger.handlers.clear()
        logger.setLevel(logging.INFO)

        fh = logging.FileHandler("server.log")
        fh.setLevel(logging.INFO)

        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)

        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh.setFormatter(formatter)
        sh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(sh)
        self._logger = logger

    def client_handle(self,connection, address):
        self._logger.info(f"Connection with {address[0]}:{address[1]} started")
        

        if self._is_connection_encrypted:
            protocol_message = json.dumps({"encryption": 1, "public_key": self.__public})
            connection.sendall(str.encode(protocol_message) + b"\0")

            stop = False
            while True:
                encoded_data = b""
                while not encoded_data.endswith(b"\0"):
                    recv_data = connection.recv(2048)

                    encoded_data = encoded_data + recv_data
                    if not recv_data:
                        stop = True
                        break
                if stop:
                    break
                encoded_data = encoded_data[:-1]
                data = self.__decryptor.decrypt(encoded_data).decode('utf-8')
                self._logger.info(f"{address[0]}:{address[1]} | In: '{data}'")
                if data == "stop":
                    self.__stop_server = True

                reply = {"error_code": 0, "error_message": ""}

                try:
                    request = json.loads(data)
                    process_output = self._route["method"](request)
                except json.JSONDecodeError:
                    reply["error_code"]= 1
                    reply["error_message"] = "Please provide a valid JSON string."
                except KeyError:
                    reply["error_code"]= 2
                    reply["error_message"] = "Your JSON string need to have a valid method key."
                else:
                    reply.update(process_output)
                
                reply_message = json.dumps(reply)

                connection.sendall(str.encode(reply_message)+b"\0")
                self._logger.info(f"{address[0]}:{address[1]} | Out: '{reply_message}'")

        else:
            protocol_message = json.dumps({"encryption": 0, "public_key": ""})
            connection.sendall(str.encode(protocol_message) + b"\0")

            stop = False
            while True:
                data = b""
                while not data.endswith(b"\0"):
                    recv_data = connection.recv(2048)
                    data = data + recv_data
                    if not recv_data:
                        stop = True
                        break
                if stop:
                    break
                data = data[:-1]
                data = data.decode('utf-8')
                self._logger.info(f"{address[0]}:{address[1]} | In: '{data}'")
                if data == "stop":
                    self.__stop_server = True

                reply = {"error_code": 0, "error_message": ""}

                try:
                    request = json.loads(data)
                    process_output = self._route[request["method"]](request)
                except json.JSONDecodeError:
                    reply["error_code"]= 1
                    reply["error_message"] = "Please provide a valid JSON string."
                except KeyError:
                    reply["error_code"]= 2
                    reply["error_message"] = "Your JSON string need to have a method key."
                else:
                    reply.update(process_output)
                reply_message = json.dumps(reply)

                connection.sendall(str.encode(reply_message)+b"\0")
                self._logger.info(f"{address[0]}:{address[1]} | Out: '{reply_message}'")


        self._logger.info(f"Connection with {address[0]}:{address[1]} closed")
        connection.close()

    def run(self):
        host = self.__host
        port = self.__port
        self._logger.info("Starting server")
        ServerSocket = socket.socket()
        ServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ServerSocket.bind((host, port))
        except socket.error as e:
            self._logger.error(str(e))
            return 1
        self._logger.info("Waiting for a Connection..")
        ServerSocket.listen(5)
        while True:
            Client, address = ServerSocket.accept()
            start_new_thread(self.client_handle, (Client, address))
            if self.__stop_server:
                break
        ServerSocket.close()


if __name__ == "__main__":

    def echo(Request):
        try:
            message = Request["message"]
        except KeyError:
            reply = {"error_code": 2, "error_message": "Please provide a 'message' key"}
        else:
            reply = {"message": message}
        return reply

    myServ = Server({"echo": echo}, auto_encrypt=True)
    myServ.run()
