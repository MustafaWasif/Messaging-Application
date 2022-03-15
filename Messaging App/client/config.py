from threading import Lock, Event
from encryption import User

#thread lock needed for resource contention - stdout file descriptor
lock = Lock()

#event object such that the clients' two threads can synchronize with eachother.
shared_event = Event()
shared_event.clear()

#variable to store username of the client at other end of connection - share between threads
#mainly needed for the receiver-side client to determine who to send to in its SendThread
connections = {}
connected_username = None

#User encryption class representing all needed information for correct X3DH key agreement & and AES-GCM encryption.
username = None