# Debugging Tips for Keychain-PKCS11

If Keychain-PKCS11 does not work for you, the VERY first thing you should
check is to see if the Apple Smartcard drivers are working.  The easiest
way to do that is run the following command (with a Smartcard plugged
into a reader and the reader plugged into your system):

```
% security list-smartcards
com.apple.pivtoken:00000000000000000000000000000000
```

If you get something like the above output (the value after
`com.apple.pivtoken` may vary) then your Smartcard is recognized by
Apple and should function correctly with Keychain-PKCS11.  If you
get a message like "No smartcards found", then the native drivers
do NOT recognize your Smartcard and will not function.

Assuming your reader and card are working correctly, the main reason for
the built-in Smartcard drivers not working are that they have been
disabled by a previous installation of the older third-party tokend
interface.  To determine if the built-in smartcard drivers have been
disabled.


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

Also, any third-party token daemons should be uninstalled.  These are
typically installed in `/Library/Security/tokend`.  These actions
will affect any applications that require on the older tokend-based
SmartCard support, so should be carefully tested.

## Debug logging

Keychain-PKCS11 does a fair amount of logging using the Unified Logging
support available in High Sierra and above . All logging is done at the
`debug` level so by default it is not captured, but it can be selected
via the Console application or the `log` command.  To see the debug log
output using `log`, run:

```
% log stream --predicate 'subsystem = "mil.navy.nrl.cmf.pkcs11"' --level debug
```

This will produce a lot of output, so you may want to redirect this to a file.

## Support

I do not provide any official support for Keychain-PKCS11 outside of the
NRL or HPC community.  I do provide ad-hoc support when I have available
time, and I always welcome bug reports.  I can be reached at
[kenh@cmf.nrl.navy.mil](mailto:kenh@cmf.nrl.navy.mil).
