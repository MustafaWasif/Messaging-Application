from threading import Event

#required globals for the program
connections = {}        #client username as index; Socket connection obj as value
authorized_users = {}   #UNUSED in this version - will be used to check duplicate sessions within the same user account

#event object such that two ServerThreads can synchronize with eachother (for chat establishment)
shared_event = Event()
shared_event.clear()