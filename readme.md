# Cryptography and Computer Security Course Projects

In this project, I implemented AES algorithm, and added functionality to run in ECB, CBC, and OFB modes.

Additionally, I developed a tool for data integrity. It creates a hash value for a given file using AES in CBC mode, then adds this value to end of the file.
After doing this operation, you can send the file securely. The reciever checks the file using this tool. If someone has modified the file, the reciever can detects it.

More details are written in report.