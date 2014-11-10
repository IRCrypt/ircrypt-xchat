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

Windows (using HexChat - experimental)

 - Download the latest stable version of [HexChat](http://hexchat.github.io/downloads.html)
    - Install HexChat on your system
    - Make sure to enable the Python support
    - Select Python 2.7.x as runtime
 - Download GnuPG vrom <http://gnupg.org> ([direct link](http://mirrors.dotsrc.org/gcrypt/binary/))
    - Install the application
    - Find out the path to the `gpg.exe`. Should be something like 
      `C:\Program Files (x86)\GNU\GnuPG\bin\gpg.exe`
 - Download `https://raw.githubusercontent.com/IRCrypt/ircrypt-xchat/master/ircrypt.py`
    - Save `ircrypt.py` to `%USERPROFILE%\AppData\Roaming\HexChat\addons`
 - Launch HexChat
    - Enable the IRCrypt plug-in (if that does not happen automatically)
    - Join an IRC network and channel. For testing IRCrypt, you might want to
      join #ircrypt on freenode.
    - Set the path to the gpg binary by typing
      `\ircrypt set-option binary C:\Program Files (x86)\GNU\GnuPG\bin\gpg.exe`


Configuration
-------------

To set up encryption for a channel simply add a passphrase to use by typing
into (he)xchat:

```
/ircrypt set-key #CHANNEL PASSPHRASE
```
