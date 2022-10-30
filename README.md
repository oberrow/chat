# Description
chat server and client coded in c*

<sub><sup>*the gui is coded in c++ using wxWidgets</sup></sub>
# How to use
## Server:<br></br>
Open a command prompt window in the directory that chat_server is in
`C:/chat_server>`
<br>Type in chat_server
`C:/chat_server>chat_server`
<br>Click enter
<br>It will crash
<br>To fix the crash type `chat_server --make_salt`
`C:/chat_server/chat_server --make_salt`
<br>Type in chat_server again
`C:/chat_server/chat_server`
<br>You will see that it says 'Listening on port 443!'

C:/chat_server>chat_server
Listening on port 443!
It binds to the ip localhost:443 by default if you want to change that then use the command line argument --ip <br> Syntax: `--ip [ip address to bind to]`<br> Notes: The ip **must** be in numerical form (eg. 163.445.91.34)
<br>To change the port it binds to use the command line argument --port<br>Syntax: `--port [port to bind to]`
<br>Use `--help` or `-h` for more command line arguments
<br>**NOTE** You **must** have an ssl certificate and private key to use this and both of the files **must** be in .pem format and the files should be in the same directory as the server executable
### Example:
`C:/chat_server>chat_server --ip 123.456.78.9 --port 12345`
## Client (chat_client.exe is no longer supported):
Double Click chat_client_gui.exe
<br>Note how it crashed
<br>The reason it crashed is because it was looking for 'Config.txt' but couldn't find it so you need to make it yourself
<br>How to make:
<br>First make a file with the name 'Config.txt' in the same directory as chat-client-gui
<br>Then copy the template below and replace everything with [] to the appropriate values
<br>Config File Syntax:
```
string ip = [server ip in numerical form]
string theme = [dark|black]
int port = [server port]
```
