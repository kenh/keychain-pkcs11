/*
 * Our header file defining the various data structures and tables to map
 * between Cryptoki constants and Security framework parameters
 *
 * Users of this header file will need to include the correct headers
 * from Cryptoki and the Security framework
 */

struct mechanism_map {
	/*
	 * Cryptoki information.
	 *
	 * The key usage flags indicates all possible things we support, but
	 * we don't necessarily support that for each key.
	 */
	CK_MECHANISM_TYPE	cki_mech;	/* Cryptoki mechanism name */
	CK_ULONG		min_keylen;	/* Minimum key length */
	CK_ULONG		max_keylen;	/* Maximum key length */
	CK_FLAGS		usage_flags;	/* Key usage flags */
	/*
	 * Security framework values
	 *
	 * The references to the key and digest algoritms are pointers
	 * to the constants, as we can't have the actual values of the
	 * variables resolved at compile/link time.  That just means
	 * we need to dereference those when we use them.
	 *
	 * The digest is used when you have to use the SecTransform API
	 * and you are using a mechanism that specifies a particular
	 * digest.  The digestlen is used for SHA2 mechanisms that have
	 * varying digest lengths; if you don't need that, just set it
	 * to 0.
	 */
	const SecKeyAlgorithm	*sec_encmech;	/* Security mech for enc */
	const SecKeyAlgorithm	*sec_signmech;	/* Security mech for sign */
	const CFStringRef	*sec_digest;	/* Digest type used */
	unsigned int		sec_digestlen;	/* Digest length */
};

extern struct mechanism_map keychain_mechmap[];
extern unsigned int keychain_mechmap_size;
