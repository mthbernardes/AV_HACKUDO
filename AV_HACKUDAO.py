import win32api
from antivirus.realtime import real_time
from threading import Thread
from datetime import datetime

def realtimescan():
	var = real_time()
	for drive in win32api.GetLogicalDriveStrings().split('\000')[:-1]:
		t = Thread(target=var.verify_files, args=(drive,))
		t.start()
	print 'Real-Time malware scan started'
	print datetime.now()
	print '-' * 50

realtimescan()