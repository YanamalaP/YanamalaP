import ftplib
from pathlib import Path

import paramiko as paramiko

ssh_client=paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh_client.connect(hostname= 'hostname',username='mokgadi',password='mypassword')
stdin,stdout,stderr=ssh_client.exec_command("ls")
print(stderr.readlines)

stdin, stdout, stderr = ssh.exec_command("sudo ls")
stdin.write('mypassword\n')

print(stdout.readlines())

#Downloading a file from remote machine
ftp_client=ssh_client.open_sftp()
ftp_client.get('remotefileth','localfilepath')
ftp_client.close()

#Uploading file from local to remote machine
ftp_client=ssh.open_sftp()
ftp_client.put('localfilepath','remotefilepath')
ftp_client.close()

# local file name you want to upload
filename = "some_file.txt"



"""# Fill Required Information
HOSTNAME = "ftp.dlptest.com"
USERNAME = "dlpuser@dlptest.com"
PASSWORD = "eUj8GeW55SvYaswqUyDSm5v6N"

# Connect FTP Server
ftp_server = ftplib.FTP(HOSTNAME, USERNAME, PASSWORD)

# force UTF-8 encoding
ftp_server.encoding = "utf-8"

# Enter File Name with Extension
filename = "File Name"

# Read file in binary mode
with open(filename, "rb") as file:
    # Command for Uploading the file "STOR filename"
    ftp_server.storbinary(f"STOR {filename}", file)

# Get list of files
ftp_server.dir()

# Close the Connection
ftp_server.quit()
"""
print("........................")