Google's Cloud Shell has an undocumented v2 API which supports establishing TCP connection to arbitrary TCP IP:port destinations.
From security point of view, this is an attack vector, so I built a client tool to play with this feature. 
(I did not manage to establish connections to anything sensitive, e.g. internal IP addresses or the metadata server.)

