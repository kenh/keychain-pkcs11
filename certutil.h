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
 * Calculate hash function; first two arguments are passed into
 * SecDigestTransformCreate().
 *
 * Returns CFDataRef on success (must be released) and NULL on failure
 */

extern CFDataRef get_hash(CFTypeRef, CFIndex length, CFDataRef);
