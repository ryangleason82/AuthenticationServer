# Authentication Server
The objective of this project was to create a server authentication system that authenticates users who provide credentials for that server to store and retrieve objects. 

## Steps 
- Receive username and password as input
- Compute 16 byte random salt from OpenSSL random number generator
- Append salt to password
- Create cryptographic hash function and store it in key-value-store
- Associate objects with user to ensure correct retrieval of information

