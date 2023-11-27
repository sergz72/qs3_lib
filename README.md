# qs3_lib

Simple UDP protocol for messages up to 420 bytes from client to server and up to 65488 bytes from server to client


Client message structure (RSA encoded, maximum request data length ~ 420 bytes for RSA 4096):

|AES key - 32 bytes|AES gcm nonce - 12 bytes|Request data|sha256 of request data - 32 bytes|


Server message structure:

|Response + sha256 of response data encrypted with AES-GCM|
