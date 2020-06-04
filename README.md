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

## Getting Started

Currently Keychain-PKCS11 is considered &ldquo;beta quality&rdquo;,
but is available either via a standard MacOS X Installer package or
you can compile it yourself.  For MacOS X Installer packages see the
[releases](https://github.com/kenh/keychain-pkcs11/releases) page on
Github.  The Installer packages are signed and notarized and should work
on any MacOS X system from High Sierra up to and including Catalina.

If you wish to use the pre-built Installer package, go to the
[releases](https://github.com/kenh/keychain-pkcs11/releases) page and
select the desired version.  The latest release is always recommended.

If you wish the compile the package from source, see **Prerequisites**
and **Installing** below.

### Prerequisites

To compile this software, you will need EITHER Xcode or the Command Line
Developer Tools package.  You can download Xcode from the App Store and you
can download the Command Line Developer Tools by running the following command:

```
xcode-select --install
```

If you are compiling from a Git repository instead of a distribution
tarfile, you will **also** need the following packages:

* Autoconf (at least version 2.69)
* Automake (at least version 1.15)
* libtool (at least version 2.4.6)

All of these packages are available via popular open-source
package systems such as Homebrew or MacPorts.

### Installing

If you are starting with a cloned Git repository, you will first need to
generate the configure scripts.  This step is not necessary if you are
using a distribution tar file.

```
% ./autogen.sh
```

Next you need to run `configure`, `make`, and `make install`.  `configure`
can take all of the standard options supported by Autoconf.

```
% ./configure
% make
% make install
```

This will install `keychain-pkcs11.dylib`, by default in `/usr/local/lib`
(the last step may need to be performed by root, depending on the permissions
in your target installation directory). You
can change the install location by using the `--prefix` option to `configure`.
See `configure --help` for more information.

### System Configuration

Once you have installed `keychain-pkcs11.dylib`, simply configure your various
applications to use this as a PKCS#11 module.  How you do that is application
dependent.

To make sure that your Smartcards are recognized by the Security framework,
you can execute (with your Smartcard inserted into the reader):

```
% security list-smartcards
com.apple.pivtoken:00000000000000000000000000000000
```

If you get something like the above output then it should work fine.  If
you get `No smartcards found`, then either there is a problem with your
reader or Smartcard, or you've disabled the Apple Smartcard framework.
To check to see if the Apple Smartcard framework has been disabled, run

```
% security smartcards token -l
```

If you see something returned like `com.apple.CryptoTokenKit.pivtoken`, then
that means the internal Smartcard support has been disabled.  You can
re-enable it by running:

```
% sudo security smartcards token -e com.apple.CryptoTokenKit.pivtoken
```

Substitute the appropriate value returned by `security smartcards token -l`.

## Configuration & Debugging

In a perfect world, Keychain-PKCS11 should just work and you shouldn't need
to do any debugging, but just in case ...

Keychain-PKCS11 does a fair amount of logging using the Unified
Logging support available in Sierra.  All logging is done at the `debug`
level so by default it is not captured, but it can be selected via
the Console application or the `log` command.  To see the debug log output
using `log`, run:

```
% log stream --predicate 'subsystem = "mil.navy.nrl.cmf.pkcs11"' --level debug
```

This will produce a lot of output, so you may want to redirect this to a file.

A man page is installed that details various different defaults you can
change using **defaults(1)**; see **keychain-pkcs11(8)**.

## Caveats

Currently Keychain-PKCS11 supports almost all PKCS#11
cryptographic functions, including `C_Sign`, 'C_SignUpdate', `C_Verify`,
'C_VerifyUpdate', `C_Encrypt`, and `C_Decrypt`.  In addition to the
basic PKCS #1 v1.5 RSA mechanism (**CKM_RSA_PKCS**), it also supports
the OAEP mechanisms for encryption/decryption and the PSS mechanisms for
signing/verification.  Note that arbitrary OAEP and PSS mechanism parameters
are NOT supported, due to limitations of the Apple Security framework, but
commonly used parameters should work.

By default Keychain-PKCS11 will return the `CKF_PROTECTED_AUTHENTICATION_PATH`
flag in the token information structure to indicate that the PIN should NOT
be input by the application using `C_Login`, but instead will be entered in
out-of-band (the Security framework will automatically bring up a dialog box
when you go to use the private key).   But if your application is buggy
in this regard or you prefer to have the application prompt for the PIN,
you can configure Keychain-PKCS11 to NOT set the
`CKF_PROTECTED_AUTHENTICATION_PATH`
flag by changing the
`askPIN` preference key via the following command:

```
% defaults write mil.navy.nrl.cmf.pkcs11 askPIN -array-add <appname>
```

Where `<appname>` is the name of the application (specifically, the
value returned by the `getprogname()` function).  If you are unsure what
that is, you can view what Keychain-PKCS11 thinks it is by viewing the
debug log (see above).

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
people still associate "Keychain" with Apple.  So I've decided to stick
with the name for now.
