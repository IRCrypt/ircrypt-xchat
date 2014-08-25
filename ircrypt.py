__module_name__ = 'IRCrypt'
__module_version__ = 'Snapshot'
__module_description__ = 'IRCrypt: Encryption layer for IRC'

ircrypt_help_text = '''
Add, change or remove key for nick or channel.

IRCrypt command options:

list                                                 List keys, special ciphers and options
set-key         [-server <network>] <target> <key>    Set key for target
remove-key      [-server <network>] <target>          Remove key for target
set-cipher      [-server <network>] <target> <cipher> Set specific cipher for channel
remove-cipher   [-server <network>] <target>          Remove specific cipher for channel
set-option                          <option> <value>  Set an option of IRCrypt

Set the key for a channel:
  /ircrypt set-key #IRCrypt key
Remove the key:
  /ircrypt remove-key #IRCrypt
Set the key for a user:
  /ircrypt set-key nick key
Switch to a specific cipher for a channel:
  /ircrypt set-cipher #IRCrypt TWOFISH
Unset the specific cipher for a channel:
  /ircrypt remove-cipher #IRCrypt
Set option CIPHER to AES
  /ircrypt set-option CIPHER AES
'''

import string, os, subprocess, base64, time, xchat

# Global buffers used to store message parts, configuration options, keys, etc.
ircrypt_msg_buffer = {}
ircrypt_keys = {}
ircrypt_ciphers = {}
ircrypt_options = {'CIPHER': 'TWOFISH'}
ircrypt_gpg_binary = None

# Constants used throughout this script
MAX_PART_LEN     = 300
MSG_PART_TIMEOUT = 300 # 5min
class MessageParts:
	'''Class used for storing parts of messages which were split after
	encryption due to their length.'''

	modified = 0
	last_id  = None
	message  = ''

	def update(self, id, msg):
		'''This method updates an already existing message part by adding a new
		part to the old ones and updating the identifier of the latest received
		message part.
		'''
		# Check if id is correct. If not, throw away old parts:
		if self.last_id and self.last_id != id+1:
			self.message = ''
		# Check if the are old message parts which belong due to their old age
		# probably not to this message:
		if time.time() - self.modified > MSG_PART_TIMEOUT:
			self.message = ''
		self.last_id = id
		self.message = msg + self.message
		self.modified = time.time()


def ircrypt_decrypt_hook(word, word_eol, userdata):

	global ircrypt_msg_buffer, ircrypt_keys, ircrypt_gpg_binary

	if '>ACRY' in word_eol[0]:
		if '>ACRY-0' in word_eol[0]:
			xchat.command('NOTICE %s :>UCRY-NOASYM' % word[0])
		return xchat.EAT_ALL

	# get context
	con = xchat.get_context()

	# Get channel and server from context
	channel = con.get_info('channel')
	server = con.get_info('network')
	nick = word[0]
	target = '%s/%s' % (server, channel)

	# Get key
	key = ircrypt_keys.get('%s/%s' % (server, channel))
	if key:
		# if key exists and >CRY part of message start symmetric encryption
		if '>CRY-' in word_eol[0]:

			pre, message    = string.split(word_eol[0], '>CRY-', 1)
			number, message = string.split(message, ' ', 1 )
			message = string.split(message, ' ', 1)[0]

			# Get key for the message buffer
			buf_key = '%s.%s.%s' % (server, channel, nick)

			# Decrypt only if we got last part of the message
			# otherwise put the message into a globa buffer and quit
			if int(number) != 0:
				if not buf_key in ircrypt_msg_buffer:
					ircrypt_msg_buffer[buf_key] = MessageParts()
				ircrypt_msg_buffer[buf_key].update(int(number), message)
				return xchat.EAT_ALL

			# Get whole message
			try:
				message = message + ircrypt_msg_buffer[buf_key].message
			except KeyError:
				pass

			# Decrypt
			p = subprocess.Popen([ircrypt_gpg_binary, '--batch',  '--no-tty', '--quiet',
				'--passphrase-fd', '-', '-d'],
				stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			p.stdin.write('%s\n' % key)
			p.stdin.write(base64.b64decode(message))
			p.stdin.close()
			decrypted = p.stdout.read()
			p.stdout.close()

			# Get and print GPG errors/warnings
			err = p.stderr.read()
			p.stderr.close()
			if err:
				con.prnt('GPG reported error:\n%s' % err)

			# Remove old messages from buffer
			try:
				del ircrypt_msg_buffer[buf_key]
			except KeyError:
				pass

			con.emit_print(userdata, nick, decrypted)

			return xchat.EAT_XCHAT

	# Not decrypted
	return xchat.EAT_NONE

def ircrypt_encrypt_hook(word, word_eol, userdata):

	global ircrypt_keys, ircrypt_ciphers, ircrypt_options, ircrypt_gpg_binary

	# Get context
	con = xchat.get_context()

	# Get channel and server from context
	channel = con.get_info('channel')
	server = con.get_info('network')
	target = '%s/%s' % (server, channel)
	if target in ircrypt_keys:

		# Get cipher
		cipher = ircrypt_ciphers.get('%s/%s' % (server, channel))
		if not cipher:
			cipher = ircrypt_options['CIPHER']

		# encrypt message
		p = subprocess.Popen([ircrypt_gpg_binary, '--batch',  '--no-tty', '--quiet',
			'--symmetric', '--cipher-algo',
			cipher,
			'--passphrase-fd', '-'],
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		p.stdin.write('%s\n' % ircrypt_keys[target])
		p.stdin.write(word_eol[0])
		p.stdin.close()
		encrypted = base64.b64encode(p.stdout.read())
		p.stdout.close()

		# Get and print GPG errors/warnings
		err = p.stderr.read()
		p.stderr.close()
		if err:
			con.prnt('GPG reported error:\n%s' % err)

		xchat.emit_print('Your Message', xchat.get_info('nick'), word_eol[0])

		# If too long for one message, split and send
		if len(encrypted) > MAX_PART_LEN:
			xchat.command('PRIVMSG %s :>CRY-1 %s' % (channel, encrypted[MAX_PART_LEN:]))

		# Send (rest)
		xchat.command('PRIVMSG %s :>CRY-0 %s' % (channel, encrypted))

		return xchat.EAT_ALL

def ircrypt_notice_hook(word, word_eol, userdata):

	# No key exchange
	if '>WCRY' in word_eol[0]:
		if '>WCRY-0' in word_eol[0]:
			xchat.command('NOTICE %s :>UCRY-NOEXCHANGE' % word[0])
		return xchat.EAT_ALL

	return xchat.EAT_NONE


def ircrypt_command_hook(word, word_eol, userdata):

	global ircrypt_keys, ircrypt_ciphers, ircrypt_options

	# Get context
	con = xchat.get_context()

	# list
	if len(word) == 1 or word[1] == 'list':
	# Print keys, special cipher and options in current context
		if ircrypt_keys:
			con.prnt('\nKeys:')
			for servchan,key in ircrypt_keys.iteritems():
				con.prnt('%s : %s' % (servchan, key))

		if ircrypt_ciphers:
			con.prnt('\nSpecial Cipher:')
			for servchan,spcip in ircrypt_ciphers.iteritems():
				con.prnt('%s : %s' % (servchan, spcip))

		if ircrypt_options:
			con.prnt('\nOptions:')
			for option, value in ircrypt_options.iteritems():
				con.prnt('%s : %s' % (option, value))
		return xchat.EAT_ALL

	# Set options
	if word[1] == 'set-option':
		if len(word) < 4:
			con.prnt(param)
			return xchat.EAT_ALL
		value = ' '.join(word[3:])
		ircrypt_options[word[2]] = value
		# Print status message to current context
		con.prnt('Set option %s to %s' % (word[2], value))
		return xchat.EAT_ALL

	if not word[1] in ['buffer', 'set-key', 'remove-key',
			'set-cipher', 'remove-cipher']:
		con.prnt('Unknown command. Try  /help ircrypt')
		return xchat.EAT_ALL

	# Check if a server was set
	if (len(word) > 3 and word[2] == '-server'):
		server_name = word[3]
		del word[3]
		del word[2]
	else:
		# Try to determine the server automatically
		server = con.get_info('network')

	# All remaining commands need a server name
	if not server:
		# if no server was set print message in ircrypt buffer and throw error
		con.prnt('Unknown Server. Please use -server to specify server')
		return xchat.EAT_ALL

	param = 'Not enough parameter. Try /help ircrypt'

	# For the remaining commands we need at least one additional argument
	if len(word) < 3:
		con.prnt(param)
		return xchat.EAT_ALL

	target = '%s/%s' % (server, word[2])

	# Set keys
	if word[1] == 'set-key':
		if len(word) < 4:
			con.prnt(param)
			return xchat.EAT_ALL
		ircrypt_keys[target] = ' '.join(word[3:])
		# Print status message to current context
		con.prnt('Set key for %s' % target)
		return xchat.EAT_ALL

	# Remove keys
	if word[1] == 'remove-key':
		if len(word) < 3 :
			con.prnt(param)
			return xchat.EAT_ALL
		# Check if key is set and print error in current context otherwise
		if target not in ircrypt_keys:
			con.prnt('No existing key for %s.' % target)
			return xchat.EAT_ALL
		# Delete key and print status message in current context
		del ircrypt_keys[target]
		con.prnt('Removed key for %s' % target)
		return xchat.EAT_ALL

	# Set special cipher for channel
	if word[1] == 'set-cipher':
		if len(word) < 4:
			con.prnt(param)
			return xchat.EAT_ALL
		ircrypt_ciphers[target] = ' '.join(word[3:])
		# Print status message to current context
		con.prnt('Set special cipher for %s' % target)
		return xchat.EAT_ALL

	# Remove secial cipher for channel
	if word[1] == 'remove-cipher':
		if len(word) < 3 :
			con.prnt(param)
			return xchat.EAT_ALL
		# Check if cipher is set and print error in current context otherwise
		if target not in ircrypt_ciphers:
			con.prnt('No existing special cipher for %s.' % target)
			return xchat.EAT_ALL
		# Delete cipher and print status message in current context
		del ircrypt_ciphers[target]
		con.prnt('Removed special cipher for %s' % target)
		return xchat.EAT_ALL

	# Set option
	if word[1] == 'set-option':
		if len(word) < 4:
			con.prnt(param)
			return xchat.EAT_ALL
		ircrypt_ciphers[target] = ' '.join(word[3:])
		# Print status message to current context
		con.prnt('Set special cipher for %s' % target)
		return xchat.EAT_ALL

	# Error if command was unknown
	return xchat.EAT_NONE


def ircrypt_init():

	global ircrypt_keys, ircrypt_options, ircrypt_ciphers

	# Open config file
	f = None
	try:
		f = open('%s/ircrypt.conf' % xchat.get_info('xchatdirfs'), 'r')
	except:
		pass
	if not f :
		xchat.prnt('Could not open ircrypt.conf.')
		return xchat.EAT_ALL

	for line in f:
		# Read keys
		if line[0:4] == 'key:':
			(prefix, target, key) = line.split(':',2)
			ircrypt_keys[target] = key[0:-1]
		else:
			# Read options
			if line[0:7] == 'option:':
				(prefix, option, value) = line.split(':',2)
				ircrypt_options[option] = value[0:-1]
			else:
				# Read special cipher
				if line[0:7] == 'cipher:':
					(prefix, target, cipher) = line.split(':',2)
					ircrypt_ciphers[target] = cipher[0:-1]

	xchat.prnt('IRCrypt re(loaded)')
	return xchat.EAT_ALL


def ircrypt_unload(userdata):
	global ircrypt_keys, ircrypt_options, ircrypt_ciphers

	# Open config file
	f = open('%s/ircrypt.conf' % xchat.get_info('xchatdirfs'), 'w')
	if not f :
		xchat.prnt('Could not open ircrypt.conf.')
		return xchat.EAT_ALL

	# write keys
	for target in ircrypt_keys:
		f.write('key:%s:%s\n' % (target, ircrypt_keys[target]))

	# write options
	for option in ircrypt_options:
		f.write('option:%s:%s\n' % (option, ircrypt_options[option]))

	# write special cipher
	for target in ircrypt_ciphers:
		f.write('cipher:%s:%s\n' % (target, ircrypt_ciphers[target]))

	return xchat.EAT_ALL


def ircrypt_find_gpg_binary():
	'''Check for GnuPG binary to use
	:returns: Tuple with binary name and version.
	'''
	for binary in ('gpg2','gpg'):
		try:
			p = subprocess.Popen([binary, '--version'],
					stdout=subprocess.PIPE,
					stderr=subprocess.PIPE)
			version = p.stdout.read().split('\n',1)[0]
			if p.wait():
				continue
			return binary, version
		except:
			pass
	return None, None


def ircrypt_check_binary():
	'''If binary is not set, try to determine it automatically
	'''
	global ircrypt_gpg_binary
	ircrypt_gpg_binary = ircrypt_options.get('BINARY')
	if ircrypt_gpg_binary:
		return
	ircrypt_gpg_binary,version = ircrypt_find_gpg_binary()
	if not ircrypt_gpg_binary:
		xchat.prnt('Automatic detection of the GnuPG binary failed and '
				'nothing is set manually. You wont be able to use IRCrypt like '
				'this. Please install GnuPG or set the path to the binary to '
				'use.')
	else:
		xchat.prnt('Found %s' % version)
		ircrypt_options['BINARY'] = ircrypt_gpg_binary

def test(word, word_eol, userdata):


	xchat.prnt(word[-2])
	return xchat.EAT_ALL

# Initialize
ircrypt_init()

# Chek if gpg binary is set
ircrypt_check_binary()

# hook for ircrypt command
xchat.hook_command('ircrypt', ircrypt_command_hook, help=ircrypt_help_text)

# hook for encryption
xchat.hook_command('', ircrypt_encrypt_hook)

# hook for decryption
xchat.hook_print('Channel Message', ircrypt_decrypt_hook, 'Channel Message')

# hook to check for asymmetric encryption in notices
xchat.hook_print('Notice', ircrypt_notice_hook)

# Unload
xchat.hook_unload(ircrypt_unload)
