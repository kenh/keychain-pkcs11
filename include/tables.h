/*
 * Our header file defining the various data structures and tables to map
 * between Cryptoki constants and Security framework parameters
 *
 * Users of this header file will need to include the correct headers
 * from Cryptoki and the Security framework
 *
 * A larger explanation about "sign algorithms" vs "digest sign algorithms":
 *
 * The Apple Security framework currently (as of this writing) doesn't
 * have a way of doing a multi-part signature operation (where data is
 * digested in chunks and then signed/verified by a private or public key).
 * So all of the signature algorithms have TWO algorithms - one designed to
 * take raw data, digest it and sign it as a single operation, and one
 * designed to take an already-generated digest and just sign that data.
 * The algorithms that take raw data to be signed all have "Message"
 * in their name and the ones that take an already-generated digest
 * have "Digest" in their name.  So we have to know both algorithms
 * in case the caller decides to use a multi-part signing operation.
 *
 * In theory you could use the SecTransform API to do a multi-part
 * signature operation, but aside from the general pain of the SecTransform
 * API (multi-part operations require creating a bound CFStream pair
 * and running the SecTransform operation in a separate thread), but
 * that doesn't work currently with keys on smartcards.
 */

enum mech_params { NONE, OAEP, PSS };

struct mechanism_map {
	/*
	 * Cryptoki information.
	 *
	 * The key usage flags indicates all possible things we support, but
	 * we don't necessarily support that for each key.
	 *
	 * "mech_params" is the type of parameters this mechanism takes.
	 */
	CK_MECHANISM_TYPE	cki_mech;	/* Cryptoki mechanism name */
	CK_ULONG		min_keylen;	/* Minimum key length */
	CK_ULONG		max_keylen;	/* Maximum key length */
	CK_FLAGS		usage_flags;	/* Key usage flags */
	enum mech_params	parameters;	/* Mechanism parameters  */

	/*
	 * Security framework values
	 *
	 * The references to the encryption algorithms are pointers
	 * to the constants, as we can't have the actual values of the
	 * variables resolved at compile/link time.  That just means
	 * we need to dereference those when we use them.
	 *
	 * We USED to use the SecTransform API to perform digest functions
	 * but it turns out that isn't required and the CommonCrypto
	 * routines are quicker and easier.  There is a specific function
	 * to call for each different digest, so to make things easier
	 * we have abstracted all of that in the ccglue functions and you
	 * pass in the mechanism type.  Rather than use Security framework
	 * values to represent the digest, I am using the PKCS#11 types
	 * to represent digest types.
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
	CK_MECHANISM_TYPE	sec_digest;	/* Digest type used */
	bool			blocksize_out;	/* Is block size output? */
};

extern const struct mechanism_map keychain_mechmap[];
extern const unsigned int keychain_mechmap_size;

/*
 * Table used for mapping beween Cryptoki algorithms/parameters
 * and Apple Security constants.
 */

struct param_map {
	CK_MECHANISM_TYPE	base_type;	/* Base mechanism type */
	CK_MECHANISM_TYPE	hash_alg;	/* Hash algorithm used */
	CK_RSA_PKCS_MGF_TYPE	mgf;		/* Message Gen Function used */
	CK_ULONG		slen;		/* Salt length (PSS) */
	const SecKeyAlgorithm	*encalg;	/* Encryption algorithm type */
	const SecKeyAlgorithm	*signalg;	/* Signature algorithm type */
	const SecKeyAlgorithm	*dsignalg;	/* Digest signature algorithm */
};

extern const struct param_map keychain_param_map[];
extern const unsigned int keychain_param_map_size;

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

extern const struct keymap keytype_map[];
