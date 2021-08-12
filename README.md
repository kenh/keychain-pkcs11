# Keychain-PKCS11

This is a library designed to bridge the gap between the Apple Security
Framework and applications which support using a PKCS#11 interface to
access cryptographic hardware.

On Sierra and above Apple includes a reasonable Smartcard implementation
but it only provides access to the Smartcard functions via the modern
Security Framework APIs (you can no longer access smartcards via the
older deprecated CDSA APIs).  If you have applications which haven't
been updated OR you have applications which support PKCS#11, then you're
either stuck with two options:

* Not using those applications
* Disabling the included Smartcard support and using a third-party
interface which provides a PKCS#11 library, at the cost of losing functionality like support for integrated Smartcard login and possibly support by
native applications.

Keychain-PKCS11 is designed to bridge this gap.  It provides a PKCS#11
library interface for applications which can use it, but it interfaces
directly with the Smartcard support in Sierra; this allows the
simultaneous use of PKCS#11 applications and native Security framework
applications.

Keychain-PKCS11 is implemented with modern APIs that are all supported
currently on Sierra, with an eye towards long-term compatibiity
with Apple-provided APIs.

Currently Keychain-PKCS11 has been tested with:

- Firefox (for smartcard access to web pages).
- Thunderbird (for smartcard-based email signing and decryption)
- MIT Kerberos (for PKINIT support)
- Adobe Acrobat Reader DC
- Ssh (to use with smartcard-based RSA keys, and can serve as a replacement
  for Apple's `ssh-keychain.dylib`).

## How to Use

The basic steps for getting using Keychain-PKCS11 are:

1. Install Keychain-PKCS11.  The best way to do that is via the
   installer package, found on the
   [GitHub release page](https://github.com/kenh/keychain-pkcs11/releases).
   That page includes signed installer packages that should work with
   any version of MacOS X from High Sierra onwards.
2. Configure your applications to use Keychain-PKCS11.  The library
   is installed in `/usr/local/lib/keychain-pkcs11.dylib`.  How each
   application is configured unfortunately varies by application.
   For Firefox and Thunderbird the library is configured as "Security Device"
   under the "Privacy & Security" preference.  In general, there should
   be some kind of configuration file or preference dialog where you
   can give the location of a PKCS#11 module; that is where you need to
   put the pathname of the Keychain-PKCS11 library.

Once your application is configured, it should just work with any available
PIV-compliant smartcards.  There is some configuration and debugging available
from the library; run `man keychain-pkcs11` at a Terminal prompt for
information on how to change the library's behavior.  Also see
[Keychain-PKCS11 debugging](https://github.com/kenh/keychain-pkcs11/blob/master/DEBUGGING.md) for more debugging tips.

## Technical Details

Keychain-PKCS11 provides a PKCS#11 interface to the Apple Security
Framework.  It does NOT support the deprecated CDSA framework.  It
leverages the existing Smartcard drivers that are supplied with OS X
and does NOT implement any smartcard drivers itself.  As of this writing,
Apple only supports Smartcards which adhere to the PIV standard and
Smartcard readers which support the USB CCID interface.

Keychain-PKCS11 provides access to all detected Smartcards
as a series of PKCS#11 'slots' starting at zero.  Keychain-PKCS11 can
also optionally provide a read-only interface to existing certificates
stored in system Keychains; see `man keychain-pkcs11` for more details.

By default Keychain-PKCS11 will set the `CKF_PROTECTED_AUTHENTICATION_PATH`
flag in the token information struct returned by `C_GetTokenInfo`.  This
should notify compliant applications that PIN prompts will happen externally
and the Security framework will cause a GUI PIN prompt when an access is made
to a private key object.  This can be disabled on a per-application bases;
see `man keychain-pkcs11`, specifically the information on `askPIN` for
more information.

Keychain-PKCS11 only supports RSA cryptosystems at this time.  The following
PKCS#11 mechanisms are supported:

- CKM_RSA_PKCS
- CKM_SHA1_RSA_PKCS, CKM_SHA224_RSA_PKCS, CKM_SHA256_RSA_PKCS,
  CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS
- CKM_RSA_PKCS_OAEP
- CKM_RSA_PKCS_PSS
- CKM_SHA1_RSA_PKCS_PSS, CKM_SHA224_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS,
  CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS
- CKM_RSA_X_509 (decrypt only)

Due to limitations of the Apple Security framework, arbitrary parameters
for OAEP and PSS cryptosystems are not supported.  For example, no
encoding parameter is supported for OAEP, and the only salt length
supported for PSS mechanisms is one that matches the length of the
chosen message hash.  No multipart encryption mechanisms are supported
at this time.

Sandboxed applications or programs that run in the hardended runtime enviroment
must be granted the `com.apple.security.smartcard` entitlement to
use Keychain-PKCS11.

If you wish to build Keychain-PKCS11 from source, please read
[README-devel](https://github.com/kenh/keychain-pkcs11/blob/master/README-devel.md)
for more information.

## Author

* **Ken Hornstein** - [kenh@cmf.nrl.navy.mil](mailto:kenh@cmf.nrl.navy.mil)

## Acknowledgments

* This code was inspired by
[KeychainToken](https://github.com/slushpupie/KeychainToken).  None of that
code could actually be used as it was based on the old APIs (and made calls
to OpenSSL), but I used it for inspiration (I also took the `pkcs11_test`
program from that distribution).
* I used the Smartcard support in
[Chrome](https://chromium.googlesource.com/chromium/src/) to get me
pointed in the right direction in terms of which Security Framework
APIs to use.

### About the name

I realize that "Keychain-PKCS11" isn't quite a good name, since in the
new framework Smartcards don't appear in your keychain, and it doesn't
actually call any Keychain functions (although it does call functions
like `SecItemCopyMatching()` which can search keychains).  I took the
original name from KeychainToken and at the beginning I wasn't sure what
functions were needed to make this work.  But at this point I can't
think of a better name.  "Security-PKCS11" sounds too generic, and
people still associate "Keychain" with Apple.  In theory this perhaps
should be called "CryptoTokenKit-PKCS11", but it doesn't really call
any CryptoTokenKit functions directly with the exception of the `TKToken`
watcher interface.  So I've decided to stick with the current name for now.
