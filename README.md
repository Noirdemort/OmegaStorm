# OmegaStorm
Anonymous Python Chatting software

The program makes use of websockets to communicate with Server.

The temporary RSA key for every session is generated and used for to and fro communication by the server.


The idea is to hide data behind loads of noise generated due to traffic itself.

**The update facility is to be fixed**
:- It is to be made concurrent with chat input and some bugs to be fixed. 

**Some bug in server side too. :- after last commit**

To try, first run server then client.


# TODO

- ## Users can write their own filters to filter what they can see. The idea is that friend groups would create their own "protocols" to talk to each other. Community members could also publish protocols and share encoders/decoders.
Maybe just use a single channel for everything
