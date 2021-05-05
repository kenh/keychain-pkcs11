# Keychain-PKCS Development

The average user should be able to use Keychain-PKCS11 without having
to compile it from source.  But if you are curious ...

## Prerequisites

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
package systems such as Homebrew or MacPorts (I would personally
recommend [Homebrew](https://brew.sh/)).

## Installing

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

For reference, I build the distribution using the following configure line:

```
% ./configure 'CC=xcrun -sdk macosx11.1 clang' 'OBJC=xcrun -sdk macosx11.1 clang' 'CFLAGS=-mmacosx-version-min=10.13 -arch x86_64 -arch arm64 -Wall -O2' 'OBJCFLAGS=-mmacosx-version-min=10.13 -arch x86_64 -arch arm64 -O2 -Wall'
```

The distribution Makefile also supports the following special targets:

- `product` - Generate a product archive using the distribution
  files in the `packaging` directory.  If there is a code signing identity
  found by Autoconf in the keychain, that will be used to sign the
  product archive.  Note that you will need both a Developer ID Application and
  a Developer ID Installer code signing identity to properly
  sign the product archive.  (The Application identity is used to sign
  the actual library, where the Installer is used to sign the product archive).
- `notarize` - This takes a product archive created by the `product` target
  and submits to the Apple notarization service.  To make this work you
  will need to have an app-specific password registered for your developer
  account.  You will need to pass the notarization userid and notarization
  password in via the `NOTARIZATION_ID` and `NOTARIZATION_PW` configure
  variables.  See `altool(1)` for the options available for `NOTARIZATION_PW`.
  If notarization is successful, this target will also staple the notarization
  ticket to the product archive.

## General source code layout

- `keychain-pkcs11.c` - The main driver for Keychain-PKCS#11.  It contains all
  of the PKCS#11 entry points and does the majority of the work of the
  module.
- `ccglue.c` - Glue routines to provide an interface to the Apple Common
  Crypto routines (used at this point just to provide hash functions)
- `certutil.c` - Routines that require more detailed examination of
  a X.509 certificate.  This makes use of the ASN.1 decoding routines
  available in the Apple Security framework.  I choose to use the Apple
  routines because I did not want to have a dependency on a library
  like OpenSSL.
- `debug.c` - Routines that map various PKCS#11 constants to strings,
  mostly used by internal logging functions.
- `tokenwatcher.m` - Routines that use TKTokenWatcher to watch for token
  insertion/removal.
- `localauth.m` - An interface to LAContext API that allows Keychain-PKCS11
  to optionally feed a PIN in via the PKCS#11 API if requested.  The
  comments have more detail.
