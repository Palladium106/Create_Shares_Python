#This script creates shared folders for users in your company
#In the 'path' it creates shares named as department
#In this folders it creates private folder for each user in department
#Private user folder will be accessible by himself, manager of department and specified admin users

import csv
import codecs
import os, sys
import configparser
import logging
import win32security
import ntsecuritycon as con

#This function assigns access rights for folders.
#Argument 'rights' can be 'F' for full access, 'R' for read only, 'W' for read and write or 'L' for list folder content rights.
#'inherit' argument controlls the inheritance. It may be set to 'I' or '' to enable or diseble rights inheritance.
def assign_acls (users: list, folder, rights, inherit):
	#print(users)
	acls = {
		'F': con.GENERIC_ALL,
		'R': con.FILE_GENERIC_READ,
		'W': con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
		'L': con.FILE_LIST_DIRECTORY

	}
	inheritance = {
		'': 0,
		'I': con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE,
	}
	#Getting DACL's
	sd = win32security.GetFileSecurity(folder, win32security.DACL_SECURITY_INFORMATION)
	dacl = sd.GetSecurityDescriptorDacl()
	#Adding DACLs
	for user in users:
		print('User = ' + user)
		userx, domain, type = win32security.LookupAccountName ("", user.strip())
		#Adding access rules
		dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inheritance[inherit], acls[rights], userx)
		print('Setting up "' + rights + '" rights for user ' + user + ' for folder ' + folder)
	sd.SetSecurityDescriptorDacl(1, dacl, 0)
	win32security.SetFileSecurity(folder, win32security.DACL_SECURITY_INFORMATION, sd)

if not os.path.exists("CreateShares.conf"):
	logging.error('Configuration file not found')
	raise Exception('Configuration file must be stored in the same folder with the script!')
#Parsing config file
config = configparser.ConfigParser()
config.read("CreateShares.conf", encoding="utf-8")
#Path to create shared folders
path = config["general"]["path"].strip('"')
#Domain controller name
DC = config["general"]["DC"]
#Orgainizational unit to export users from
OU = 'OU=' + config["general"]["OU"]
print(OU)
#Split FQDN like 'sgp-it.ru' and join it to be like 'DC=sgp-it,DC=ru'
FQDN = 'DC=' + ',DC='.join(config["general"]["FQDN"].split('.'))
print('FQDN: ' + FQDN)
#Administrator rights users
admins = config["general"]["admins"].split(',')
print('Admins list: ' + str(admins))
#List only rights users
listgroup = config["general"]["listgroup"]
print('List only access group name: ' + str(listgroup))
#Managers of departments key words
managers = config["general"]["managers"].split(',')
print('Managers list: ' + str(managers))
#Delimiter between surname and initials
delimiter = config["naming_rules"]["delimiter"].strip('"')
print('Delimiter: "' + delimiter + '"')

#Configuring logging
logging.basicConfig(filename=config["general"]["LogFile"], format='%(asctime)s - %(levelname)s: %(message)s', level=logging.DEBUG, encoding='utf-8')


print('Exporting users from ' + OU)
logging.info('Exporting users from %s', OU)
#Using scvde to export users list
result = os.system('csvde -s ' + DC +' -d "' + OU +',' + FQDN +'" -p SubTree -f Users.csv -r "(&(objectCategory=person)(objectClass=user)(!useraccountcontrol=514)(!useraccountcontrol=546)(!useraccountcontrol=66050))" -l "department, mail, telephonenumber, mobile, title, givenName, sn, sAMAccountName, dn" -u')
if result:
	logging.error('Users export failed')
	raise Exception('Users export failed')
#Making folders and setting permissions
with codecs.open('Users.csv', 'rb', 'utf-16') as file:
	users = csv.DictReader(file)
	userslist = []
	#Parsing CSV file in list of parameters
	for row in users:
		ous = row['DN'].split(',')
		#Reversing DN field for the right order of OU sequence
		ous.reverse()
		#Deleting all OUs list before root OU index and deleting all elements that not contains 'OU='
		ous = ous[ous.index(OU)+1::]
		ous = list(x.replace('OU=', '') for x in ous if x.find('OU=') != -1)
		ous = '\\'.join(ous)
		
		curruser = [row['sAMAccountName'], row['department'], row['title'], ous, row['givenName'], row['sn']]
		userslist.append(curruser)
	#Creating root share folder
	if not os.path.exists(path):
		os.makedirs(path)
		print('Created root share folder: ' + path.split('\\')[-1])
		logging.info('Created root share folder: %s', path.split('\\')[-1])
	#Adding admin credentials with inheritance on
	assign_acls (list(admins), path, 'F', 'I')
	#Adding list only group credentials with no inheritance
	assign_acls ([listgroup], path, 'L', '')
	#Adding users credentials
	for user in userslist:
		#Adding credentials to the root folder. All users can list folder content.
		#assign_acls ([user[0]], path, 'L', '')
		#Creating share folders for OUs
		if not os.path.exists(path + '\\' + user[3]):
			os.makedirs(path + '\\' + user[3])
			print('Created department folder: ' + user[3])
			logging.info('Created department folder: %s', user[3])
		
		#Creating private folders
		initials = ''
		for word in user[4].split(' '):
			initials += word[0].upper()
		if config["naming_rules"]["SNFirst"].lower() == 'true':
			privatesharename = user[5] + delimiter + initials
		else:
			privatesharename = initials + delimiter + user[5]
		
		if not os.path.exists(path + '\\' + user[3] + '\\' + privatesharename):
			os.makedirs(path + '\\' + user[3] + '\\' + privatesharename)
			print('Created private folder: ' + privatesharename)
			logging.info('Created private folder: %s', privatesharename)
		#Addind credentails to the root folder of department. Disabling ACL inheritance for department folders.
		assign_acls ([user[0]], path + '\\' + user[3], 'L', '')
		#Adding credentials for private user folders
		assign_acls ([user[0]], path + '\\' + user[3] + '\\' + privatesharename, 'F', 'I')
		#Adding credentials for managers of department
		for manager in managers:
			#If 'title' contains key words listed in 'managers' field of the config file then giving user full access rights
			if row['title'].lower().find(manager.strip().lower())  != -1:
				print(row['title'])
				assign_acls ([user[0]], path + '\\' + user[3], 'F', 'I')
