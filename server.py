import asyncio
import websockets
import json
import random
from clint.textui import colored
import hashlib
from Crypto import Random
from Crypto.PublicKey import RSA


print(colored.green("Generating keys..."))

# creating rsa transaction keys
random_generator = Random.new().read
serverKey = RSA.generate(8192, random_generator)  # generate public and private key
publickeyServer = serverKey.publickey().exportKey()

print(colored.cyan("Keys generated."))
print(colored.blue("Encrypting connection... "))

chatDict = {}
chatBuffer = {}

print(colored.magenta("Server started..."))


# pipeline which encrypts transmitted messages before storing in temporary buffer
async def enc_pipeline(server_key, intel, room):
    icenia = {}
    for client in chatDict[room]['clients']:
        client_key = RSA.importKey(chatDict[room]['clients'][client])
        icenia[client] = client_key.encrypt(server_key.decrypt(intel), str(room))[0]
    return icenia


# stores messages and serve encrypted strings for query
async def update_record(room, operation, intel, src):
    if operation == 'query':
        try:
            data = chatBuffer[room]
            client_key = chatDict[room]['clients'][src]
            rsa_client = RSA.importKey(client_key)
            intel = b''
            for i in data:
                j = i[0]    # i[0] is msg.
                # encrypt j here
                if str(j.__class__) == "<class 'dict'>":
                    # checking if src is in dictionary or has recently joined.
                    if src in j.keys():
                        j = j[src]
                    else:
                        j = b''
                else:
                    j = rsa_client.encrypt(intel, str(room))[0]

                k = i[1]    # i[1] is src-info for msg.
                k = k.encode('utf-8')
                intel += j + "#$*@&SFG{}HJ*(@#$".format(room).encode("utf-8") + k

                intel += "*^&*AA{}AA%^&*".format(src).encode("utf-8")
            intel_hash = hashlib.sha512(intel).hexdigest()
            return intel, intel_hash

        except Exception as e:
            print(colored.red("Exception Occurred...."))
            print(e)
            return 'not', ' available'
    else:
        # simple tuple storing in a list, only 15 instances are stored as buffer.
        if room not in list(chatBuffer.keys()):
            chatBuffer[room] = [tuple((intel, src))]
        else:
            chatBuffer[room].append(tuple((intel, src)))
            if len(chatBuffer[room]) > 15:
                del chatBuffer[room][0]


# sort of main function
async def echo(websocket, path):
    while 1:
        async for message in websocket:

            msg = json.loads(message)

            if msg['operation'] == 'createRoom':

                random_seed = random.randint(10**6, 10**7)
                nonce = (random_seed + int(msg['seed'])) % (10**5)
                topic = str.encode(msg['topic'] + str(nonce), 'UTF-8', errors='strict')

                room_hash = hashlib.sha512(topic).hexdigest()    # creates room hash
                chatDict[room_hash] = {"title": msg['title'], "clients": {msg['username']: bytes(msg['publicKey'])}}
                msg = {
                    "operation": "confirmation",
                    'hash': room_hash,
                    'serverKey': list(publickeyServer),
                    'title': msg['title']
                }
                # sending room and server configuration
                await websocket.send(json.dumps(msg))

            elif msg['operation'] == 'joinRoom':

                print(colored.green("Sending hashes... "))
                choice_dict = {}

                for i in chatDict:
                    choice_dict[i] = chatDict[i]['title']
                choice_dict['operation'] = 'hashList'
                await websocket.send(json.dumps(choice_dict))    # serving join request

            elif msg['operation'] == 'hashChoice':

                chatDict[msg['roomHash']]['clients'][msg['username']] = bytes(msg['publicKey'])
                create_dict = {
                    "operation": "serverKey",
                    "serverKey": list(publickeyServer),
                    "title": chatDict[msg['roomHash']]['title']
                }
                # sending config to joining username.
                await websocket.send(json.dumps(create_dict))

                # storing information about user
                await update_record(
                    msg['roomHash'],
                    'grant',
                    "{} has joined the chat".format(msg['username']).encode('utf-8'),
                    'Server'
                )

            elif msg['operation'] == 'transmission':

                # passing intel and receiving encrypted dictionary.
                intel = await enc_pipeline(serverKey, bytes(msg['intel']), msg['room'])

                # storing intel
                await update_record(msg['room'], 'transmission', intel, msg['from'])

            elif msg['operation'] == 'disconnect':

                del chatDict[msg['room']]['clients'][msg['for']]

                # storing exit info.
                await update_record(
                    msg['room'],
                    'revoke',
                    "{} has exited the chat".format(msg['for']).encode('utf-8'),
                    'Server'
                )

            elif msg['operation'] == 'update':
                # requesting updating information on behalf of a source
                # served data is an encrypted string storing metadata.
                data = await update_record(msg['room'], 'query', b'intel', msg['from'])

                update_packet = {}
                if data[0] != 'not':
                    update_packet = {
                        "operation": "reply",
                        "whistle": list(data[0]),
                        "hash": data[1]
                    }
                else:
                    update_packet['operation'] = "does not matter"
                    # for errors on strings and avoiding injections.

                await websocket.send(json.dumps(update_packet))


print(colored.white("Listening on 8765..."))

start_server = websockets.serve(echo, 'localhost', 8765)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
