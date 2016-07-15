import win32api
import time
import logging
import os
import yara
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler  
from threading import Thread

class Rules():
	def get_rules(self,):
		rules_files = {}
		for root, dirs, files in os.walk("rules"):
			for file in files:
				if file.endswith(('.yar','.yara')):
					full_file = (os.path.join(root, file))
					rules_files[file] = full_file
		return yara.compile(filepaths=rules_files)

class RTHandler(PatternMatchingEventHandler):
	patterns = ['*.txt', '*.accdb', '*.arj', '*.bat', '*.bin', '*.boo', '*.cab', '*.chm', '*.cla', '*.class', '*.com', '*.csc', '*.dll', '*.doc', '*.docm', '*.docx', '*.dot', '*.dotm', '*.dotx', '*.drv', '*.eml', '*.exe', '*.gz', '*.hlp', '*.hta', '*.htm', '*.html', '*.htt', '*.ini', '*.jar', '*.jpeg', '*.jpg', '*.js', '*.jse', '*.lnk', '*.lzh', '*.mdb', '*.mpd', '*.mpp', '*.mpt', '*.msg', '*.mso', '*.nws', '*.ocx', '*.oft', '*.ovl', '*.pdf', '*.php', '*.pif', '*.pl', '*.pot', '*.potm', '*.potx', '*.ppam', '*.pps', '*.ppsm', '*.ppsx', '*.ppt', '*.pptm', '*.pptx', '*.prc', '*.rar', '*.reg', '*.rtf', '*.scr', '*.shs', '*.sys', '*.tar', '*.vbe', '*.vbs', '*.vsd', '*.vss', '*.vst', '*.vxd', '*.wml', '*.wsf', '*.xla', '*.xlam', '*.xls', '*.xlsb', '*.xlsm', '*.xlsx', '*.xlt', '*.xltm', '*.xltx', '*.xml', '*.z', '*.zip']
	def on_modified(self, event):
		#self.process(event)
		#print event.event_type,event.src_path
		scan().file_scan(event.src_path)
	def on_created(self, event):
		#self.process(event)
		#print event.event_type,event.src_path
		scan().file_scan(event.src_path)

class real_time(object):
	def verify_files(self,path):
		try:
			observer = Observer()
			observer.schedule(RTHandler(), path, recursive=True)
			observer.start()
			try:
				while True:
					time.sleep(1)
			except KeyboardInterrupt:
				observer.stop()
			observer.join()
		except:
			pass
			
class scan(object):
	def __init__(self,):
		self.rules = Rules().get_rules()

	def mycallback(self,data):
		yara.CALLBACK_CONTINUE

	def file_scan(self,file):
		try:
			print file
			with open(file, 'rb') as f:
				matches = self.rules.match(data=f.read(),callback=self.mycallback)
				if matches:
					for match in matches:
						pprint(match.rule)
						pprint(match.meta)
						
				else:
					print 'Clean'
			print
		except:
			#print str(e)
			pass

if __name__ == '__main__':
	var = real_time()
	for drive in win32api.GetLogicalDriveStrings().split('\000')[:-1]:
		t = Thread(target=var.verify_files, args=(drive,))
		t.start()
	print 'Real-Time malware scan started'
	print datetime.now()
	print '-' * 50
