/*
 * Prototypes for the glue functions to the CommonCrypto framework
 */

/*
 * A generic set of message digst (hash functions).  For a type
 * argument they take a PKCS#11 mechanism name, such as CKM_SHA_1
 * or CKM_SHA256.  Only cc_md_init() can return an error.
 *
 * Arguments:
 *
 * type		- A PKCS#11 mechanism type for a message digest,
 *		  like CKM_SHA_1 or CKM_SHA256.
 * context	- A context structure containing the message digest
 *		  internal state.  Allocated by cc_md_init(), freed
 *		  by cc_md_final().
 * data		- Data to be added to the message digest calculation.
 * len		- Length of data
 * ret_data	- The output of the message digest calculation.  Always
 *		  allocated, must be freed by caller
 * ret_len	- The returned length of the digest.
 */

typedef struct _md_context *md_context;

extern bool cc_md_init(CK_MECHANISM_TYPE type, md_context *context);
extern void cc_md_update(md_context context, const unsigned char *data,
			 unsigned int len);
extern void cc_md_final(md_context context, unsigned char **ret_data,
			unsigned int *ret_len);
