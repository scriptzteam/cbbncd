```
     _   _             _ 
 ___| |_| |_ ___ ___ _| |
|  _| . | . |   |  _| . |
|___|___|___|_|_|___|___|

cbbncd-0.24

This is an FTP control channel+traffic bouncer.
It works with glftpd and any other ftpd that supports IDNT.
The connection data is embedded into the executable and is (optionally)
encrypted with AES-256.

Build dependencies: make g++ openssl libssl-dev libc6-dev

To compile, run: make
You will be asked for connection details during compilation.

When encryption is selected, no potentially sensitive data will be stored
in the build directory.
When compilation is finished, everything except the executable can be
removed.

To add multiple site addresses or bind addresses (when specifying both IPv4
and IPv6 for example), just separate them with space, or comma, or semicolon.
Example: ftp.example.com:12345 ftp2.example.com:12345

To force IPv4 or IPv6 for a site address, add a (4) or (6) in front of it.
Example: (6)ftp.example.com:12345

The connection details can also be specified on the command line when
compiling, to avoid interactive questions. Example:
make PORT=65432 HOST=ftp.example.com:21 IDENT=false BIND=false TRAFFIC=false
This will compile without interaction and with data encryption disabled.
For non-interactive compilation with encryption enabled, the DATA parameter
can be used:
make DATA=encrypted-data-string
The encrypted-data-string can be retrieved by checking the resulting
BNCDATA parameter in the final link command during regular interactive
compilation.

Changelog:

0.24 (2024-01-21):
  - Added NAT external IP support
0.23 (2022-10-30):
  - Fixed leaking port listeners
  - Fixed bugs resulting in bad memory access
0.22 (2022-10-22):
  - Fixed a problem with stalled transfers when a client connection sends a
    new CPSV/PASV/EPSV before the previous transfer connections were closed
0.21 (2022-10-10):
  - Some changes for better openssl version compatibility
0.20 (2022-08-28):
  - Fixed wrong ip in PORT rewrite when different interfaces are used
    for client and site connections
0.19 (2022-08-17):
  - Workaround for IPv6 address in IDNT
  - Added support for providing multiple site addresses and round-robin
    between them (add multiple by separating with space, see above)
  - Added support for disabling IDNT completely to allow chaining
    bouncers
0.18 (2022-08-16):
  - Fixed a crash when binding to a specific ip
0.17 (2022-08-16):
  - Added support for traffic bouncing
  - Added IPv6 support
0.16 (2021-03-19):
  - Switched to a newer encryption key derivation method if available
0.15 (2021-03-12):
  - Fixed a bug from 0.14 where the port setting was ignored
  - Fixed a bug with TUN interfaces preventing interface matching
0.14 (2021-03-12):
  - Added support for binding to a specific IP or interface
  - Improved login time by connecting to server while waiting for ident
    response
  - Fixed connect bug when using implicit TLS
  - Fixed some rare crashes
0.13 (2019-12-12):
  - Improved makefile for automation purposes
0.12 (2019-12-04):
  - Fixed missing reverse DNS field in IDNT
  - Updated core lib
0.11 (2018-12-09):
  - Fixed a bug where ident lookup couldn't be disabled
0.10 (2018-12-01):
  - Added support for disabling ident lookup
0.9 (2018-10-01):
  - Fixed a bug with ident replies containing trailing newlines
0.8 (2018-01-12):
  - Fixed memory leaks
0.7 (2017-11-02):
  - Added a missing include
0.6 (2017-06-01):
  - Fixed a session handling bug that causes degraded performance over time
0.5 (2017-04-20):
  - Fixed a bug with ident responses containing spaces
0.4 (2016-12-30):
  - The passphrase entered during build is read with openssl directly to
    avoid problems with special characters
0.3 (2016-12-20):
  - Updated core lib because of a bug in socket priority handling
0.2 (2016-12-17):
  - Added encryption support
  - Updated core lib because of fixes around socket load management
0.1 (2016-12-06):
  - First release
```
