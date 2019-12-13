/*
 * Prototypes for our certificate utility functions
 */

/*
 * Returns "true" if successful, CFDataRef return pointers must be released.
 */

extern bool get_certificate_info(CFDataRef, CFDataRef *, CFDataRef *,
				 CFDataRef *);

/*
 * Find common name in an encoded X.509 Name
 *
 * Will always return an allocated string that must be free()d.
 */

extern char *get_common_name(unsigned char *, unsigned int);

/*
 * Decode modulus and public exponent from an encoded RSAPublicKey 
 */

extern bool get_pubkey_info(CFDataRef, CFDataRef *, CFDataRef *);

/*
 * Return 'true' if the given certificate is a CA
 */

extern bool is_cert_ca(SecCertificateRef);
