import os
import sys
import getpass
import time
import paramiko
from collections import OrderedDict
from os.path import expanduser

class bcolors:
	OK = '\033[92m'
	WARNING = '\033[34m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'

def open_ssh_connection():
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	print '\n########### Login ###########'
	try:
		#username = raw_input(bcolors.BOLD + '  username: ' + bcolors.ENDC)
		#hostname = raw_input(bcolors.BOLD + '  hostname: ' + bcolors.ENDC)
		#password = getpass.getpass(bcolors.BOLD + '  password: ' + bcolors.ENDC)
		username = 'root'
		hostname = '10.76.20.139'
		password = 'tetas'
		print '  Connecting...'
	
		ssh.connect(hostname, 22, username, password,timeout=10)
	except Exception as e:
		print_execution_stat('  Could not connect: ', 'FAIL', e)
		print '###############################\n'
		exit(0)
	print '###############################\n'
	
	return ssh

def choose_application(ssh):
	applications = []
	s = send_command(ssh,'ipainstaller -l').split('\n')[1:-1]

	print '\n########### Installed Applications ###########'
	
	for i,line in enumerate(s): # the first one is the command and the second one a null 
		applications.append(line)
		print "  " + str(i) + ". " + applications[i]
	
	print '################################################\n'

	num = -1
	while num < 0 or num >= len(applications):
		try:
			num = int(input('Select the application: '))
		except Exception as e:
			continue

	s = send_command(ssh,'ipainstaller -i ' + applications[num]).split('\n')[:-1]
	dictionary = {}
	for line in s:
		name = line.split(':')[0]
		content = line.split(':')[1].strip()
		dictionary[name] = content

	return dictionary

'''
def dynamic_path(ssh, app):
	ssh.sendline ('cycript -p ' + app['pid']) 
	ssh.sendline ('[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject];') 
	ssh.prompt()

	app['dynamic_path'] = ssh.before.split('"')[1].split("file://")[1].split("Documents/")[0]

	ssh.sendline ('?exit') 
	ssh.prompt()
'''

def send_command(ssh,c,t=None):
	stdin, stdout, stderr = ssh.exec_command(c,timeout=t)
	return stdout.read()

def print_execution_stat(s,stat,s2):
	if (stat == 'OK'):
		print bcolors.BOLD + s + bcolors.ENDC + bcolors.OK + str(s2) + bcolors.ENDC
	elif (stat == 'FAIL'):
		print bcolors.BOLD + s + bcolors.ENDC + bcolors.FAIL + str(s2) + bcolors.ENDC
	elif (stat == 'WARNING'):
		print bcolors.BOLD + s + bcolors.ENDC + bcolors.WARNING + str(s2) + bcolors.ENDC

def check_pie(*argv):
	ssh = argv[0]
	app = argv[1]

	try:
		s = send_command(ssh,'otool -hv ' + os.path.join(app['Application'],app['Display Name']))

		if "PIE" in s:
			app['pie'] = 0
		else:
			app['pie'] = 1
		
		if "MH_MAGIC_64" in s:
			app['cpu'] = 'ARM 64 bits'
		else:
			app['cpu'] = 'ARM 32 bits'

		print_execution_stat('  Position Independent Executable (PIE) check: ', 'OK', 'OK')
	except Exception as e:
		print_execution_stat('  Position Independent Executable (PIE) check: ', 'FAIL', e)

def check_stack(*argv):
	ssh = argv[0]
	app = argv[1]

	try:
		s = send_command(ssh, 'otool -I -v ' + os.path.join(app['Application'],app['Display Name']))

		if "stack_chk_guard" in s and "stack_chk_fail" in s:
			app['stack'] = 0
		else:
			app['stack'] = 1


		print_execution_stat("  Stack Smashing Protections check: ", 'OK', "OK")
	except Exception as e:
		print_execution_stat("  Stack Smashing Protections check: ", 'FAIL', e)

def check_arc(*argv):
	ssh = argv[0]
	app = argv[1]

	objc = [
		'_objc_retain',
		'_objc_release',
		'_objc_storeStrong',
		'_objc_releaseReturnValue',
		'_objc_autoreleaseReturnValue',
		'_objc_retainAutoreleaseReturnValue',
	]

	try: 
		s = send_command(ssh, 'otool -I -v ' + os.path.join(app['Application'],app['Display Name']) + ' | grep _objc_')
		

		if not all(x in s for x in objc):
			app['arc'] = 0
		else:
			app['arc'] = 1

		print_execution_stat("  Automatic Reference Counting (ARC) check: ", 'OK', "OK")
	except Exception as e:
		print_execution_stat("  Automatic Reference Counting (ARC) check: ", 'FAIL', e)


def get_files_by_extension(*argv):
	ssh = argv[0]
	app = argv[1]

	exts = [
		"plist",
		"sql",
		"db",
		"xml",
	]
	try:
		for ext in exts:
			app[ext] = []
			s = send_command(ssh,'find ' + app['Bundle'] + ' -iname "*.' + ext + '*"')
			
			# Es descarta la primera perque es la comanda i la ultima es un salt de linia buit
			files = s.split('\n')[1:-1] 
			app[ext] = files

		print_execution_stat("  Get sensible files: ", 'OK', "OK")
	except Exception as e:
		print_execution_stat("  Get sensible files: ", 'FAIL', e)

def convert_plist(*argv):
	ssh = argv[0]
	app = argv[1]

	try:
		for file in app['plist']:
			send_command(ssh,'plutil -convert xml1 -i ' + file)

		print_execution_stat("  Convert plist: ", 'OK', "OK")
	except Exception as e:
		print_execution_stat("  Convert plist: ", 'FAIL', e)

def print_menu(options):
	print '\n########### MENU ###########'

	for key in options:
		print "\n"+str(key)
		for i in sorted(options[key]):
			print '  {}. {}'.format(i,options[key][i][1])
	
	print '\n  0. Exit'
	print '#############################\n'

def show_app_info(*argv):
	ssh = argv[0]
	app = argv[1]

	print '\n########### APPLICATION INFO ###########\n'
	print bcolors.BOLD + 'Name: ' + bcolors.ENDC + str(app['Name'])
	print bcolors.BOLD + 'Short version: ' + bcolors.ENDC + str(app['Short Version'])
	print bcolors.BOLD + 'Version: ' + bcolors.ENDC + str(app['Version'])
	print bcolors.BOLD + 'Binary name: ' + bcolors.ENDC + str(app['Display Name'])
	print bcolors.BOLD + 'Identifier: ' + bcolors.ENDC + str(app['Identifier'])
	print bcolors.BOLD + 'Bundle: ' + bcolors.ENDC + str(app['Bundle'])
	print bcolors.BOLD + 'Data: ' + bcolors.ENDC + str(app['Data'])
	print '\n##########################################\n'

def set_key_words(*argv):
	ssh = argv[0]
	app = argv[1]
	keywords = argv[2]

	num = -1
	while num != 0:
		print "\n################# KEY WORDS MENU #################\n"
		print "  1. Show key words"
		print "  2. Add key words"
		print "  3. Delete key words"
		print "  0. Back"
		print "\n##################################################"
		try:
			num = int(input('\nSelect an option: '))
			if num == 1:
				print bcolors.BOLD + "\nKey words selected: " + bcolors.ENDC
				for key in keywords:
					print "  " + key
			elif num == 2:
				new_keyboards = raw_input('\nEnter key words to add: ').split(' ')
				for new_key in new_keyboards:
					if new_key not in keywords:
						keywords.append(new_key)
			elif num == 3:
				new_keyboards = raw_input('\nEnter key words to delete: ').split(' ')
				for new_key in new_keyboards:
					if new_key in keywords:
						keywords.remove(new_key)
			elif num == 0:
				break
		except Exception as e:
			continue

	return keywords

def set_work_path(*argv):
	ssh = argv[0]
	app = argv[1]

	num = -1
	while num != 0:
		print """
\n################# WORK PATH MENU #################\n
  1. Show current work path
  2. Set new work path
  0. Back
\n##################################################
		"""
		try:
			num = int(input('\nSelect an option: '))
			if num == 1:
				print bcolors.BOLD + "\nCurrent work path: " + bcolors.ENDC + app['workpath']
			elif num == 2:
				app['workpath'] = raw_input('\nEnter new work path: ')
			elif num == 0:
				break
		except Exception as e:
			continue


def check_keyboard(*argv):
	ssh = argv[0]
	app = argv[1]
	keywords = argv[2]

	if keywords:
		try:
			app['keyboard'] = []
			for key in keywords:
				r1 = send_command(ssh,'grep -rnw "/var/mobile/Library/Keyboard/" -e "'+key+'"')
				r2 = send_command(ssh,'grep -rnw "'+app['Data']+'/Library/Keyboard/" -e "'+key+'"')
				if r1 or r2:
					app['keyboard'].append(key)

			print_execution_stat('  Keyboard leakage check : ', 'OK', 'OK')
		except Exception as e:
			print_execution_stat('  Keyboard leakage check : ', 'FAIL', e)
	else:
		print_execution_stat('  Keyboard leakage check: ', 'WARNING', 'could not be completed, no keywords defined')

def check_pasteboard_leakage(*argv):
	ssh = argv[0]
	app = argv[1]
	keywords = argv[2]

	if keywords:
		try:
			app['pasteboard'] = []
			for key in keywords:
				r1 = send_command(ssh,'grep -rnw "/private/var/mobile/Library/Caches/com.apple.UIKit.pboard" -e "'+key+'"')
				if r1:
					app['pasteboard'].append(key)

			print_execution_stat('  Pasteboard leakage check: ', 'OK', 'OK')
		except Exception as e:
			print_execution_stat('  Pasteboard leakage check: ', 'FAIL', e)
	else:
		print_execution_stat('  Pasteboard leakage check: ', 'WARNING', 'could not be completed, no keywords defined')


def check_nsuserdefaults(*argv):
	ssh = argv[0]
	app = argv[1]
	keywords = argv[2]

	if keywords:
		try:
			app['nsuserdefaults'] = []
			for key in keywords:
				r1 = send_command(ssh,'grep -rnw "'+app['Data']+'/Library/Preferences/" -e "'+key+'"')
				if r1:
					app['nsuserdefaults'].append(key)

			print_execution_stat('  NSUserDefaults leakage check: ', 'OK', 'OK')
		except Exception as e:
			print_execution_stat('  NSUserDefaults leakage check: ', 'FAIL', e)
	else:
		print_execution_stat('  NSUserDefaults leakage check: ', 'WARNING', 'could not be completed, no keywords defined')


def check_cache(*argv):
	ssh = argv[0]
	app = argv[1]
	keywords = argv[2]

	if keywords:
		try:
			app['cache'] = []
			for key in keywords:
				r1 = send_command(ssh,'grep -rnw "'+app['Data']+'/Library/Caches/"'+app['Identifier']+' -e "'+key+'"')
				if r1:
					app['cache'].append(key)

			print_execution_stat('  Cache leakage check: ', 'OK', 'OK')
		except Exception as e:
			print_execution_stat('  Cache leakage check: ', 'FAIL', e)
	else:
		print_execution_stat('  Cache leakage check: ', 'WARNING', 'could not be completed, no keywords defined')


def basic_checks(*argv):
	ssh = argv[0]
	app = argv[1]
	options = argv[3]

	for opt in options['Basic checks']:
		keywords = options['Basic checks'][opt][0](ssh,app)
	

def login_required(*argv):
	ssh = argv[0]
	app = argv[1]
	keywords = argv[2]
	options = argv[3]
	
	for opt in options['Login required']:
		options['Login required'][opt][0](ssh,app,keywords)

def all_checks(*argv):
	ssh = argv[0]
	app = argv[1]
	keywords = argv[2]
	options = argv[3]

	for opt in options['Tests']:
		if opt != 1:
			options['Tests'][opt][0](ssh,app,keywords,options)

def show_vulnerabilities(*argv):
	app = argv[1]
	available_vulns = [
		'pie',
		'stack',
		'arc',
		'keyboard',
		'pasteboard',
		'nsuserdefaults',
		'cache',
		'encryption',
		'clutch',
		'classdump',
		'regex_search',
	]
	print '\n########### DETECTED VULNERABILITIES ###########\n'
	for vuln in available_vulns:
		if vuln == 'pie': 
			if vuln not in app:
				print ' Position Independent Executable (PIE): ?'
			elif not app[vuln]:
				print_execution_stat(' Position Independent Executable (PIE): ', 'OK', 'OK')
			else: 
				print_execution_stat(' Position Independent Executable (PIE): ', 'FAIL', 'VULNERABLE')
		if vuln == 'stack': 
			if vuln not in app:
				print ' Stack Smashing Protections: ?'
			elif not app[vuln]:
				print_execution_stat(' Stack Smashing Protections: ', 'OK', 'OK')
			else: 
				print_execution_stat(' Stack Smashing Protections: ', 'FAIL', 'VULNERABLE')
		if vuln == 'arc': 
			if vuln not in app:
				print ' Automatic Reference Counting (ARC): ?'
			elif not app[vuln]:
				print_execution_stat(' Automatic Reference Counting (ARC): ', 'OK', 'OK')
			else:
				print_execution_stat(' Automatic Reference Counting (ARC): ', 'FAIL', 'VULNERABLE')
		if vuln == 'keyboard': 
			if vuln not in app:
				print ' Keyboard leakage: ?'
			elif not app[vuln]:
				print_execution_stat(' Keyboard leakage: ', 'OK', 'OK')
			else: 
				print_execution_stat(' Keyboard leakage: ', 'FAIL', 'VULNERABLE') 
				for item in app[vuln]:
					print '\t' + item
		if vuln == 'pasteboard': 
			if vuln not in app:
				print ' Pasteboard leakage: ?'
			elif not app[vuln]:
				print_execution_stat(' Pasteboard leakage: ', 'OK', 'OK')
			else: 
				print_execution_stat(' Pasteboard leakage: ', 'FAIL', 'VULNERABLE')
				for item in app[vuln]:
					print '\t' + item
		if vuln == 'nsuserdefaults': 
			if vuln not in app:
				print ' NSUserDefaults leakage: ?'
			elif not app[vuln]:
				print_execution_stat(' NSUserDefaults leakage: ', 'OK', 'OK')
			else: 
				print_execution_stat(' NSUserDefaults leakage: ', 'FAIL', 'VULNERABLE')
				for item in app[vuln]:
					print '\t' + item
		if vuln == 'cache': 
			if vuln not in app:
				print ' Cache leakage: ?'
			elif not app[vuln]:
				print_execution_stat(' Cache leakage: ', 'OK', 'OK')
			else: 
				print_execution_stat(' Cache leakage: ', 'FAIL', 'VULNERABLE')
				for item in app[vuln]:
					print '\t' + item
		if vuln == 'encryption': 
			if vuln not in app:
				print ' Binary encryption: ?'
			elif not app[vuln]:
				print_execution_stat(' Binary encryption: ', 'OK', 'NONE')
			else: 
				print_execution_stat(' Binary encryption: ', 'FAIL', 'ENCRYPTED')
		if vuln == 'clutch': 
			if vuln not in app:
				print ' Decrypted binary: ?'
			elif app[vuln]:
				print_execution_stat(' Decrypted binary: ', 'OK', app['clutch'])
			else: 
				print_execution_stat(' Decrypted binary: ', 'FAIL', 'ERROR')
		if vuln == 'classdump': 
			if vuln not in app:
				print ' Class-Dump: ?'
			elif app[vuln]:
				print_execution_stat(' Class-Dump: ', 'OK', app['classdump'])
			else: 
				print_execution_stat(' Class-Dump: ', 'FAIL', ERROR)
		if vuln == 'regex_search': 
			if vuln not in app:
				print ' Regex search: ?'
			elif not app[vuln]:
				print_execution_stat(' Regex search: ', 'OK', 'OK')	
			else: 
				print_execution_stat(' Regex search: ', 'FAIL', 'POTENTIALLY VULNERABLE')
				for item in app[vuln]:
					print '\t' + item
	print '\n##################################################\n'

def check_encryption(*argv):
	ssh = argv[0]
	app = argv[1]

	try:
		result = send_command(ssh,'otool -arch all -Vl '+app['Application']+'/'+app['Display Name']+' | grep -A5 LC_ENCRYPT')
		for r in result.split('\n'):
			if 'cryptid' in r:
				app['encryption'] = int(list(filter(None,r.split(' ')))[1]) # Remove null positions from array
		print_execution_stat('  Check encryption: ', 'OK', 'OK')
	except Exception as e:
		print_execution_stat('  Check encryption: ', 'FAIL', e)

def decrypt_binary(*argv):
	ssh = argv[0]
	app = argv[1]

	try:
		# Obtain application id
		result = send_command(ssh,'Clutch -i')
		for r in result.split('\n'):
			if app['Identifier'] in r:
				clutch_id = str(list(filter(None,r.split(':')))[0])
				break

		# Decrypt
		result = send_command(ssh,'Clutch -n -b {}'.format(clutch_id),10)

		# Get binary clutch path
		result = send_command(ssh,'ls -lat /var/tmp/clutch')
		r = result.split('\n')[2].split(' ')[10] # drwxr-xr-x 24 root wheel  816 Jun 21 08:32 FOLDER
		if len(r) < 5:
			r = result.split('\n')[3].split(' ')[10] # sometimes the result are .  ..  FOLDER instead of . FOLDER ..
		app['clutch'] = '/var/tmp/clutch/' + str(r)

		print_execution_stat('  Decrypt binary: ', 'OK', 'OK')
	except Exception as e:
		print_execution_stat('  Decrypt binary: ', 'WARNING', 'Should be checked manually, timeout set at 10 seconds')
		
		# Get binary clutch path (exception)
		result = send_command(ssh,'ls -lat /var/tmp/clutch')
		r = result.split('\n')[2].split(' ')[10] # drwxr-xr-x 24 root wheel  816 Jun 21 08:32 FOLDER
		print r
		if len(r) < 5:
			r = result.split('\n')[3].split(' ')[10] # sometimes the result are .  ..  FOLDER instead of . FOLDER ..
		app['clutch'] = '/var/tmp/clutch/' + str(r)

def classdump(*argv):
	ssh = argv[0]
	app = argv[1]

	try:
		result = send_command(ssh, 'class-dump ' + app['Application']+'/'+app['Display Name'])
		
		file = 'classdump_'+app['Display Name']+'.txt'
		path = os.path.join(app['workpath'],file)
		with open(path, 'w') as text_file:
			text_file.write(result)

		app['classdump'] = path

		print_execution_stat('  Class-Dump: ', 'OK', 'OK')
	except Exception as e:
		print_execution_stat('  Class-Dump: ', 'FAIL', e)

def search_with_regex(*argv):
	ssh = argv[0]
	app = argv[1]

	try:
		result_regex = app['regex_search']
	except Exception as e:
		result_regex = []

	regex_found = 0
	for regex_type in app['regex']:
		if app['regex'][regex_type]['active']:
			regex_found = 1
			regex = app['regex'][regex_type]['regex']

			try:
				result_bundle = send_command(ssh, 'grep -Eo "' + regex + '" -r ' + app['Bundle'])
				result_regex += result_bundle.split('\n')[:-1]

				result_bundle = send_command(ssh, 'grep -Eo "' + regex + '" -r ' + app['Data'])
				result_regex += result_bundle.split('\n')[:-1]

				app['regex_search'] = result_regex

				print_execution_stat('  Regex search: ', 'OK', 'OK')
			except Exception as e:
				print_execution_stat('  Regex search: ', 'FAIL', e)

	if not regex_found:
		print_execution_stat('  Regex search: ', 'WARNING', 'No regex selected')

def set_regex(*argv):
	ssh = argv[0]
	app = argv[1]

	num = -1
	while num != 0:
		print "\n################# REGEX MENU #################\n"
		print "  1. Show available regex"
		print "  2. Modify regex selection"
		print "  3. Add custom regex"
		print "  4. Delete regex"
		print "  0. Back"
		print "\n##################################################"
		try:
			num = int(input('\nSelect an option: '))
			if num == 1:
				print bcolors.BOLD + "\n  Available regex: " + bcolors.ENDC
				for regex_type in app['regex']:
					if not app['regex'][regex_type]['active']:
						print '  [ ] ' + regex_type + ': ' + app['regex'][regex_type]['regex']
					else:
						print '  [x] ' + regex_type + ': ' + app['regex'][regex_type]['regex']
			elif num == 2:
				user_input = raw_input('\nEnter regex name: ').split(' ')
				for regex_name in user_input:
					app['regex'][regex_name]['active'] = (app['regex'][regex_name]['active'] + 1 )%2
			elif num == 3:
				regex_name = raw_input('\nEnter regex name: ').strip()
				regex = raw_input('\nEnter regex: ')
				app['regex'][regex_name] = {'active':1, 'regex':regex}
			elif num == 4:
				user_input = raw_input('\nEnter regex: ').split(' ')
				print user_input
				for regex_name in user_input:
					if regex_name in app['regex']:
						del app['regex'][regex_name]
			elif num == 0:
				break
		except Exception as e:
			continue


def main(args):
	OPTIONS = OrderedDict()

	OPTIONS['Tests'] = {
		1: (all_checks,'Run all checks'),
		2: (basic_checks,'Run all the basic checks'),
		3: (login_required,'Run all the login required checks')
	}
	OPTIONS['Basic checks'] = {
		4: (check_pie,'Check Position Independent Executable (PIE)'),
		5: (check_stack,'Check Stack Smashing Protections'),
		6: (check_arc,'Automatic Reference Counting (ARC)'),
		7: (get_files_by_extension,'Get sensible files'),
	}
	OPTIONS['Login required'] = {
		8: (check_keyboard,'Check keyboard leakage'),
		9: (check_pasteboard_leakage,'Check pasteboard leakage'),
		10: (check_nsuserdefaults,'Check NSUserDefaults leakage'),
		11: (check_cache,'Check cache leakage'),
	}
	OPTIONS['Binary'] = {
		12: (check_encryption,'Check if the binary is encrypted'),
		13: (decrypt_binary,'Decrypt the binary with Clutch'),
		14: (classdump,'Obtain binary headers with ClassDump'),
	}
	OPTIONS['Other'] = {
		15: (convert_plist,'Convert binary plist to XML'),
		16: (search_with_regex, 'Search using regex')
	}
	OPTIONS['Configuration'] = {
		17: (set_key_words,'Set key words'),
		18: (set_work_path,'Set work folder'),
		19: (set_regex, 'Set regex'),
	}
	OPTIONS['Results'] = {
		20: (show_app_info,'Show app basic information'),
		21: (show_vulnerabilities,'Show detected vulnerabilities'),
	}

	test_results = ['Results','Configuration'] # Avoid printing ### TEST RESULTS ### in this group

	keywords = []
	

	ssh = open_ssh_connection()
	app = choose_application(ssh)

	# By default, work path will be the home of the user
	app['workpath'] = expanduser("~")

	# Available regex
	app['regex'] = {
		'ip': {
			'active': 1,
			'regex': '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
		},
		'email': {
			'active': 1,
			'regex': '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
		},
		'dni': {
			'active': 1,
			'regex': '[0-9]{8,8}[A-Za-z]$'
		},
		'iban': {
			'active': 1,
			'regex': '[a-zA-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{7}([a-zA-Z0-9]?){0,16}'
		},
		'base64': { # TEST, not sure it works
			'active': 0,
			'regex': '(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$'
		},
	}


	option = 1
	while int(option):
		print_menu(OPTIONS)
		try:
			option = int(raw_input('Select an option: '))
			for key in OPTIONS:	
				if option in OPTIONS[key]:
					if key not in test_results:
						print "\n##################### TEST RESULTS #####################\n"
					if option == 17: # set keywords
						keywords = OPTIONS[key][option][0](ssh,app,keywords,OPTIONS)
					else:
						OPTIONS[key][option][0](ssh,app,keywords,OPTIONS)
					if key not in test_results:
						print "\n########################################################"
		except Exception as e:
			continue
		#print app

	ssh.close()


if __name__ == '__main__':
	if len(sys.argv) < 1:
		print 'Usage: ios_static_analysis.py'
		sys.exit(-1)
	main(sys.argv)	


'''
Dependencies
	Ipa installer
	paramiko
	clutch
	class dump


JSON example
Identifier: com.thenetfirm.mobile.wapicon.WapIcon
Version: 20180517145604
Short Version: 5.5.0
Name: CaixaBank
Display Name: ADAM_FULL
Bundle: /private/var/containers/Bundle/Application/5969A30A-AB84-4EC3-BF54-BEC1A8E848A6
Application: /private/var/containers/Bundle/Application/5969A30A-AB84-4EC3-BF54-BEC1A8E848A6/ADAM_FULL.app
Data: /private/var/mobile/Containers/Data/Application/4B8DFBBE-21AE-4012-8414-65B4007DA246
arc: 0
xml: []
sql: []
db: []
pie: 1
stack: 1
keyboard: ['ey','hola']
pasteboard: ['ey','hola']
nsuserdefaults: ['ey','hola']
cache: ['ey','hola']
'''
