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
	 *
	 * "blocksize_out" is true IF the output size of the mechanism is
	 * the same as the block size returned by SecKeyGetBlockSize();
	 * that lets us check to see if the given input buffer is too
	 * small, so we only need call the SecKey* functions once which
	 * will mean we only have one PIN prompt.  Currently this is "true"
	 * for all mechanisms we support, but I didn't feel confident
	 * hardcoding this for future mechanisms.
	 */
	const SecKeyAlgorithm	*sec_encmech;	/* Security mech for enc */
	const SecKeyAlgorithm	*sec_signmech;	/* Security mech for sign */
	const SecKeyAlgorithm	*sec_dsignmech;	/* Mech for sign, take dgst */
	const CFStringRef	*sec_digest;	/* Digest type used */
	unsigned int		sec_digestlen;	/* Digest length */
	bool			blocksize_out;	/* Is block size output? */
};

extern struct mechanism_map keychain_mechmap[];
extern unsigned int keychain_mechmap_size;

/*
 * Table used for mapping beween Cryptoki algorithms/parameters
 * and Apple Security constants.
 */

enum alg_family { OAEP, PSS };

struct param_map {
	CK_MECHANISM_TYPE	base_type;	/* Base mechanism type */
	CK_MECHANISM_TYPE	hash_alg;	/* Hash algorithm used */
	CK_RSA_PKCS_MGF_TYPE	mgf;		/* Message Gen Function used */
	CK_ULONG		slen;		/* Salt length (PSS) */
	enum alg_family		family;		/* Algorithm family */
	const SecKeyAlgorithm	*alg;		/* Security algorithm type */
	const SecKeyAlgorithm	*dalg;		/* Digest algorithm type */
};

extern struct param_map keychain_param_map[];
extern unsigned int keychain_param_map_size;

/*
 * Table used for mapping between Cryptoki key types and Security
 * framework key types.  The same rules apply as above; we use pointers
 * to the Security framework constants so they can be resolved at compile
 * time and will need to be dereferenced when you actually use them.
 *
 * This array is terminated by a NULL pointer for the keyname.
 */

struct keymap {
	const char	*keyname;	/* User-printable name of keytype */
	CK_KEY_TYPE	pkcs11_keytype;	/* Cryptoki constant for key type */
	const CFStringRef *sec_keytype;	/* Security constant for key type */
};

extern struct keymap keytype_map[];
