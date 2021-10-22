import socket
import os
from _thread import *
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import json
from ery4z_toolbox.utils import get_random_string, AESCipher


class Server:
    """General purpose server class with built in high level protocol. 
    """
    def __init__(self, routing, key=None, logger=None, host="127.0.0.1", port=1233, auto_encrypt=False):
        """Creator of the class 

        Args:
            routing (dict): Dict mapping the function with method name to
            key (rsa key): string, optional): RSA key in order to initialise the AES, if not provided they will be automaticly generated. Defaults to None.
            logger (logger, optional): Optionnal logger object overiding the created one. Defaults to None.
            host (str, optional): Ipv4 of the server. Defaults to "127.0.0.1".
            port (int, optional): Port of the server. Defaults to 1233.
            auto_encrypt (bool, optional): Automaticaly generate RSA and AES256 key for encryption. Defaults to False.
        """
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
        logger.setLevel(logging.ERROR)

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

    def __send_ack(self,connection,AES):
        message = json.dumps({"method": "ack"})
        if self._is_connection_encrypted:
            encrypted = AES.encrypt(message+"\1")
            connection.sendall(encrypted + b"\0")
        else:
            connection.sendall(bytes(message, "utf-8") + b"\0")

    def __receive_ack(self,connection,AES):
        encoded_data = b""
        r = False
        while not encoded_data.endswith(b"\0"):
            connection.settimeout(2.0)
            try:
                recv_data = connection.recv(1024)
            except Exception:
                r = True
            connection.settimeout(None)
            if r :
                return False


            encoded_data = encoded_data + recv_data

        
        encoded_data = encoded_data[:-1]
        self._logger.info(f"Server received raw: {encoded_data}")
        trame = AES.decrypt(encoded_data).decode('utf-8')[:-1]

        try:
            data = json.loads(trame)
        except Exception as e:
            return False
        else:
            if data["method"] == "ack":
                return True
            else:
                return False

    def client_handle(self,connection, address):
        self._logger.info(f"Connection with {address[0]}:{address[1]} started")
        client_public_key = None
        AES_manager = None


        if self._is_connection_encrypted:
            # Establishing RSA Channel
            protocol_message = json.dumps({"encryption": 1, "public_key": self.__public.decode('utf-8')})
            self._logger.debug(f"{address[0]}:{address[1]} | Out: '{protocol_message}'")
            connection.send(str.encode(protocol_message) + b"\0")

            protocol_message = connection.recv(1024)[:-1].decode("utf-8")
            self._logger.debug(f"{address[0]}:{address[1]} | In: '{protocol_message}'")
            protocol_dict_r = json.loads(protocol_message)

            


            
            try:
                if protocol_dict_r["encryption"] == 1:
                    client_public_key = protocol_dict_r["public_key"]
            except KeyError:
                pass

            if client_public_key is not None:
                client_encryptor = PKCS1_OAEP.new(RSA.import_key(client_public_key))

            # Establishing AES channel
            AES_key = get_random_string(32)
            AES_manager = AESCipher(KEY=AES_key)
            
            AES_protocol_message = json.dumps({"encryption": 1, "AES_key": AES_key})

            reply_encrypted = client_encryptor.encrypt(bytes(AES_protocol_message, "utf-8"))
            connection.send(reply_encrypted+b"\0")
            
            self._logger.debug(f"{address[0]}:{address[1]} | Out: 'AES_Key_Hidden'")

            stop = False
            while True:
                data = ""
                last_packet = ""
                while not data.endswith("\1"):
                    encoded_data = b""
                    while not encoded_data.endswith(b"\0"):

                        recv_data = connection.recv(1024)


                        encoded_data = encoded_data + recv_data
                        if not recv_data:
                            stop = True
                            break
                    if stop:
                        return 0
                    
                    encoded_data = encoded_data[:-1]
                    self._logger.info(f"Server received raw: {encoded_data}")
                    n_d = AES_manager.decrypt(encoded_data).decode('utf-8')
                    self._logger.info(f"Server received: {n_d}")
                    if n_d != last_packet:
                        data += n_d
                        last_packet = n_d
                        self.__send_ack(connection, AES_manager)

                data = data[:-1]
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
                    reply["error_message"] = "Your JSON string need to have a valid method key."
                else:
                    reply.update(process_output)
                
                reply_message = json.dumps(reply)+"\1"
                n = 24
                chunks = [reply_message[i:i+n] for i in range(0, len(reply_message), n)]
                chunk_index = 0
                while chunk_index < len(chunks):
                    chunk = chunks[chunk_index]
                    self._logger.info(f"Server send: {chunk}")
                    reply_encrypted = AES_manager.encrypt(chunk)
                    connection.send(reply_encrypted+b"\0")
                    if self.__receive_ack(connection, AES_manager):
                        chunk_index += 1
                self._logger.info(f"{address[0]}:{address[1]} | Out: '{reply_message[:-1]}'")

        else:
            protocol_message = json.dumps({"encryption": 0, "public_key": ""})
            connection.send(str.encode(protocol_message) + b"\0")

            protocol_message = connection.recv(1024)[:-1].decode("utf-8")
            self._logger.info(f"{address[0]}:{address[1]} | In: '{protocol_message}'")
            protocol_dict_r = json.loads(protocol_message)

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

                connection.send(str.encode(reply_message)+b"\0")
                self._logger.info(f"{address[0]}:{address[1]} | Out: '{reply_message}'")


        self._logger.info(f"Connection with {address[0]}:{address[1]} closed")
        connection.close()

    def run(self):
        host = self.__host
        port = self.__port
        self._logger.info("Starting server")
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
