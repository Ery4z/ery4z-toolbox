from ..ery4z_toolbox import Server, Client
import random
import time, json
from threading import Thread
import tqdm

def s_run():
    def echo(Request):
            try:
                message = Request["message"]
            except KeyError:
                reply = {"error_code": 2, "error_message": "Please provide a 'message' key"}
            else:
                reply = {"message": message}
            return reply

    myServ = Server.Server({"echo": echo}, auto_encrypt=True)
    myServ.run()

def c_run():
    myClient = Client.Client()
    myClient.connect()

    time_elapsed = []
    data = []
    test_count = 10
    data_count = 180000
    data_range = 3000
    error_count = 0
    

    for i in range(data_count):
        data.append(random.random() * data_range)

    data = {"method": "echo", "message": data}
    message = json.dumps(data)

    for i in tqdm.tqdm(range(test_count)):
        
        
        
        t_start = time.time()
        myClient.send(message)

        response = myClient.receive()
        time_elapsed.append(time.time() - t_start)
        try:
            d = json.loads(response)["message"]
        except Exception as e:
            print(response)
            error_count += 1
        else:

            if d != data["message"]:
                print(response)
                error_count += 1

    print(f"Error {error_count} | Mean time elapsed: {sum(time_elapsed)/len(time_elapsed)}")

Server_thread = Thread(target=s_run)
#Client_thread = Thread(target=c_run)
Server_thread.start()
time.sleep(2)
#Client_thread.start()
c_run()


#Client_thread.join()
Server_thread.join()
