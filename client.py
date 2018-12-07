import asyncio
import time
import websockets
import json
import hashlib
from Crypto import Random           # for random seed generation
from Crypto.PublicKey import RSA
from getpass import getpass         # for PassPhrase secure input
from clint.textui import colored    # printing colored text
from tqdm import tqdm               # animation for iterables



print(colored.red("\n\t\t Project Ω-Storm\n"))

print(colored.blue("Starting ß–protocols... "))

print(colored.green("Generating keys..."))
random_generator = Random.new().read
key = RSA.generate(4096, random_generator)  # generate public and private key for client
publickey = key.publickey().exportKey()     # export public key
print(colored.cyan("Keys generated. "))

print(colored.blue("Encrypting connection... \n"))

username = input(colored.green("Enter your username: "))
passPhrase = getpass(colored.red("Enter pass-phrase for this session: "))
joinOrCreate = input(colored.magenta("Join or create chat-room (j for join and c for create): "))

topic = input(colored.cyan("Enter topic for chat-room: "))

if joinOrCreate not in ['join', 'j']:
    crTitle = input(colored.cyan("Enter title for chat-room: "))
    nonce = int(input(colored.blue("Enter a seed value: ")))


# function for connecting to server
async def initiate(url):
    global serverKey
    global hashChoice
    async with websockets.connect(url) as websocket:

        if joinOrCreate not in ['join', 'j']:

            createDict = {
                "operation": "createRoom",
                "topic": topic,
                "title": crTitle,
                'publicKey': list(publickey),
                "seed": nonce,
                "username": username
            }

            # sending user data to server
            createDict = json.dumps(createDict)
            await websocket.send(createDict)
            global serverKey

            # waiting for server public-key
            response = await websocket.recv()
            response = json.loads(response)
            print(colored.green("\n Created room with title :- {}".format(crTitle)))
            print(colored.green("\n HASH for room is :- {}\n".format(response['hash'])))
            serverKey = bytes(response['serverKey'])    # server public-key
            hashChoice = response['hash']               # noting hash of the current room

        else:

            createDict = {
                "operation": "joinRoom",
            }
            createDict = json.dumps(createDict)
            await websocket.send(createDict)    # sending join request to server
            hashDict = await websocket.recv()   # recieving hashlist from server
            hashDict = json.loads(hashDict)
            hashlist = list(hashDict.keys())
            print(colored.blue("Generating hashes..."))
            choiceList = {}

            # generating hashlist for current topic
            for i in tqdm(range(10**6, 10**7)):
                tnc = str.encode(topic+str(i), 'UTF-8', errors='strict')
                chatHash = hashlib.sha512(tnc).hexdigest()
                if chatHash in hashDict.keys():
                    choiceList[chatHash] = hashDict[chatHash]

            print(colored.blue('Uploading to server...'))
            j = 0
            print(colored.white("\n Code ------ Title"))
            for msg in choiceList:
                print("{}.   \t  {}".format(j+1, choiceList[msg]))
                j += 1
            del j
            hashChoice = int(input("Enter the chat-room you want to enter: "))
            hashlist = list(choiceList.keys())
            hashChoice = hashlist[hashChoice-1]


            createDict = {
                "operation": "hashChoice",
                "username": username,
                'publicKey': list(publickey),
                'roomHash': hashChoice
            }

            print("Connecting to {}...".format(choiceList[hashChoice]))
            # sending chosen hash to server
            createDict = json.dumps(createDict)
            await websocket.send(createDict)
            response = await websocket.recv()
            response = json.loads(response)
            serverKey = bytes(response['serverKey'])
            # recieved server public-key


# for sending and checking messages
async def hello(url):
    lastMSG = ''
    async with websockets.connect(url) as websocket:
        # flag = -1
        while 1:
            # while 1:
                # flag = -1
                msg = input(colored.cyan("{}-# >> ".format(username)))
                # flag = 0

                if msg not in ['\q', 'exit', 'quit', 'close']:
                    if msg == 'update()':
                        lastMSG = await checkShift(url, lastMSG)
                    elif msg=='':
                        pass
                    else:
                        msg = str.encode(msg, 'UTF-8', errors='strict')
                        msg = serverKey.encrypt(msg, passPhrase)
                        msg = msg[0]

                        msgDict = {
                            "operation": "transmission",
                            "from": username,
                            "room": hashChoice,
                            "intel": list(msg)
                        }
                        await websocket.send(json.dumps(msgDict))
                    # print("Message Delivered")
                else:
                    msgDict = {
                        "operation": "disconnect",
                        "room": hashChoice,
                        "for": username
                    }
                    # print("reached here")
                    await websocket.send(json.dumps(msgDict))
                    # print("reached here 2")
                    break



# for displaying recieved messages
async def checkShift(url,lastMSG):
    async with websockets.connect(url) as websocket:
            print('checking update...')
            #sending update query
            createDict = {
                "operation": "update",
                'room': hashChoice,
                'from': username
            }
            await websocket.send(json.dumps(createDict))
            msg = await websocket.recv()
            msg = json.loads(msg)

            # receiving message
            if msg['operation'] == 'reply':
                decrypted = bytes(msg['whistle'])
                if msg['hash'] == hashlib.sha512(decrypted).hexdigest():
                    #checked hash validity
                    decrypted = decrypted.split("*^&*AA{}AA%^&*".format(username).encode("utf-8"))
                    if key.decrypt(decrypted[-1].split('#$*@&SFG{}HJ*(@#$'.format(hashChoice).encode('utf-8'))[0]) == lastMSG:
                        print('lastMatch')  # checking if message is same as previous one.
                    else:
                        # print(decrypted)
                        for item in decrypted:
                            item = item.split('#$*@&SFG{}HJ*(@#$'.format(hashChoice).encode('utf-8'))

                            if len(item) > 1:
                                item[0] = key.decrypt(item[0])
                                if item[1] == b'Server':
                                    print(colored.blue("\t\t {}".format(item[0])))  # message from server
                                elif item[1] == username.encode('utf-8'):
                                    pass
                                    # pthis section to avoid printing message by the user itself.
                                else:
                                    print(colored.green("{} >> {}".format(item[1], item[0])))
                                lastMSG = item[0]

            return lastMSG


url = 'ws://localhost:8765'


asyncio.get_event_loop().run_until_complete(
   initiate('ws://localhost:8765')
)
# import server public key in proper format
serverKey = RSA.importKey(serverKey)

asyncio.get_event_loop().run_until_complete(
    hello('ws://localhost:8765')
)
asyncio.get_event_loop().run_forever()

