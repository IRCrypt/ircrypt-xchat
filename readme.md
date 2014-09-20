(he)xchat-ircrypt
=================

This is an implementation of the [IRCrypt protocol
](https://github.com/IRCrypt/documentation) for XChat and its forks like
HexChat. It provides an encryption layer for IRC using standardized and well
proven techniques for encryption.

This plug-in is still work-in-progress, but can already be used to send and
receive messages encrypted with cryptographically strong symmetric ciphers
within regular channels. Private conversations are not yet encrypted.


Requirements
------------

 - (he)xchat with support for Python extensions
 - GnuPG


Installation
------------

Linux:

```
   curl -o $HOME/.config/hexchat/addons/ircrypt.py \
      https://raw.githubusercontent.com/IRCrypt/ircrypt-xchat/master/ircrypt.py
```

Windows (experimental)

 - Make sure `gpg.exe` or `gpg2.exe` is in your Windows system path
 - Download `https://raw.githubusercontent.com/IRCrypt/ircrypt-xchat/master/ircrypt.py`
 - Copy `ircrypt.py` to `%USERPROFILE%\AppData\Roaming\HexChat\addons`


Configuration
-------------

To set up encryption for a channel simply add a passphrase to use by typing
into (he)xchat:

```
/ircrypt set-key #CHANNEL PASSPHRASE
```
