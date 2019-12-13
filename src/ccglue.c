/*
 * Glue routines to interface with the Apple CommonCrypto framework
 */

#include <CommonCrypto/CommonCrypto.h>

#include "mypkcs11.h"
#include "ccglue.h"

struct _md_context {
	CK_MECHANISM_TYPE	type;
	union {
		CC_SHA1_CTX	sha1;
		CC_SHA256_CTX	sha256;		/* Also used for SHA224 */
		CC_SHA512_CTX	sha512;		/* Also used for SHA384 */
	} state;
};

/*
 * Initialize the appropriate digest function and return "false" on error
 */

bool
cc_md_init(CK_MECHANISM_TYPE type, md_context *context)
{
	md_context ctx = malloc(sizeof(*ctx));

	ctx->type = type;

	switch (type) {
	case CKM_SHA_1:
		CC_SHA1_Init(&(ctx->state.sha1));
		break;
	case CKM_SHA224:
		CC_SHA224_Init(&(ctx->state.sha256));
		break;
	case CKM_SHA256:
		CC_SHA256_Init(&(ctx->state.sha256));
		break;
	case CKM_SHA384:
		CC_SHA384_Init(&(ctx->state.sha512));
		break;
	case CKM_SHA512:
		CC_SHA512_Init(&(ctx->state.sha512));
		break;
	default:
		free(ctx);
		return false;
	}

	*context = ctx;
	return true;
}

/*
 * Update the hash state with new data
 */

void
cc_md_update(md_context context, const unsigned char *data, unsigned int len)
{
	switch (context->type) {
	case CKM_SHA_1:
		CC_SHA1_Update(&(context->state.sha1), data, len);
		break;
	case CKM_SHA224:
		CC_SHA224_Update(&(context->state.sha256), data, len);
		break;
	case CKM_SHA256:
		CC_SHA256_Update(&(context->state.sha256), data, len);
		break;
	case CKM_SHA384:
		CC_SHA384_Update(&(context->state.sha512), data, len);
		break;
	case CKM_SHA512:
		CC_SHA512_Update(&(context->state.sha512), data, len);
		break;
	}
}

/*
 * Finalize the hash algorithm, return the digest, and then free the
 * digest state
 */

void
cc_md_final(md_context context, unsigned char **ret_data,
	    unsigned int *ret_len) 
{
	unsigned int len;
	unsigned char *d;

	switch (context->type) {
	case CKM_SHA_1:
		len = CC_SHA1_DIGEST_LENGTH;
		break;
	case CKM_SHA224:
		len = CC_SHA224_DIGEST_LENGTH;
		break;
	case CKM_SHA256:
		len = CC_SHA256_DIGEST_LENGTH;
		break;
	case CKM_SHA384:
		len = CC_SHA384_DIGEST_LENGTH;
		break;
	case CKM_SHA512:
		len = CC_SHA512_DIGEST_LENGTH;
		break;
	}

	d = malloc(len);

	switch (context->type) {
	case CKM_SHA_1:
		CC_SHA1_Final(d, &(context->state.sha1));
		break;
	case CKM_SHA224:
		CC_SHA224_Final(d, &(context->state.sha256));
		break;
	case CKM_SHA256:
		CC_SHA256_Final(d, &(context->state.sha256));
		break;
	case CKM_SHA384:
		CC_SHA384_Final(d, &(context->state.sha512));
		break;
	case CKM_SHA512:
		CC_SHA512_Final(d, &(context->state.sha512));
		break;
	}

	free(context);
	*ret_data = d;
	*ret_len = len;
}
