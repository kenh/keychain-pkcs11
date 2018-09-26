/*
 * Utility routines for dealing with various things about certificates
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecDigestTransform.h>

#include "certutil.h"
#include "keychain_pkcs11.h"
#include "config.h"

/*
 * These are the arrays we need to feed into the Security framework
 * DER decoder so we can extract out the information we need.
 *
 * It turns out that we can't use the Security framework functions like
 * SecCertificateCopyNormalizedSubjectSequence(), because THOSE return
 * "normalized" DER sequence (hence the name) which are really designed
 * for searching using SecItemCopyMatching; specifically, the ASCII
 * characters in those DER sequences have been converted to upper case.
 * And as it turns out, that messes up some applications (Firefox) because
 * they look up the certificate public and private key objects based on
 * the subject from the certificate, AND since the normalized subject
 * doesn't match the ACTUAL subject, the certificate will never be selected
 * as valid client certificates.
 *
 * I spun my wheels for a while on the problem; I thought about parsing the
 * ASN.1 sequence by hand (ugh) or constructing the encoded name based
 * on info returned by SecCertificateCopyValues (that doesn't preserve the
 * string information).  But then I realized that the Security framework
 * decoder routines could stash the DER encoded Name in a buffer, and
 * that seemed the more robust solution.  It was just a pain to figure out
 * how the DER routines work.
 */

/*
 * Our ASN.1 template array; each entry in the template corresponds to
 * another field in the ASN.1 structure.
 *
 * Since all we care about is the issuer and subject, we skip the actual
 * decoding of most fields with SEC_ASN1_SKIP.  The version is a bit weird,
 * so we have to specify the explict tag and use kSecAsn1SkipTemplate.
 *
 * Using SEC_ASN1_SAVE saves the raw DER bytes into a SecAsn1Item structure.
 * But because of the way the ASN.1 decoder works, you need to still run it
 * through the parser, so you need the SEC_ASN1_SKIP after SEC_ASN1_SAVE.
 * SEC_ASN1_SKIP_REST terminates the decoding immediately.
 *
 * The fields of SecAsn1Template are, in order:
 *
 * kind		- The tag of this field.  We use SEQUENCE to indicate the start
 *		  of a new sequence, SKIP to skip over this field (this will
 *		  prevent any data from being decoded/saved) and SAVE (which
 *		  saves the raw DER bytes without decoding).
 * offset	- Offset into the passed-in structure to store this data.
 * sub		- A sub-template for nested structures; we don't use this
 *		  (except for the version, because it was the easiest way
 *		  to make it work).
 * size		- For some cases (SEC_ASN1_GROUP, SEC_ASN1_INLINE, and a few
 *		  others) the ASN.1 decoder can allocate a sub-structure for
 *		  you; this is how big it would be.
 *
 * We don't do much verification of the fields of the certificate, but I
 * figure that the Security framework probably wouldn't have it available
 * if it was unparseable.
 */

struct certinfo {
	SecAsn1Item	serialnumber;	/* Certificate serial number */
	SecAsn1Item	issuer;		/* Certificate issuer */
	SecAsn1Item	subject;	/* Certificate subject */
};

/*
 * This is where the magic happens!  Basically a description of an X.509
 * certificate, with most of the fields skipped
 */

static const SecAsn1Template cert_template[] = {
	{ SEC_ASN1_SEQUENCE, 0, NULL, 0 },	/* Certificate sequence */
	{ SEC_ASN1_SEQUENCE, 0, NULL, 0 },	/* TBCertificate sequence */
	{ SEC_ASN1_EXPLICIT | SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_CONTEXT_SPECIFIC | 0, 0, kSecAsn1SkipTemplate, 0 },
					/* Version (explicit tag 0) */
	{ SEC_ASN1_SAVE, offsetof(struct certinfo, serialnumber), NULL, 0 },
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* CertificateSerialNumber */
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* AlgorithmIdentifier */
	{ SEC_ASN1_SAVE, offsetof(struct certinfo, issuer), NULL, 0 },
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* Issuer */
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* Validity */
	{ SEC_ASN1_SAVE, offsetof(struct certinfo, subject), NULL, 0 },
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* Subject */
	{ SEC_ASN1_SKIP_REST, 0, NULL, 0 },	/* Stop decoding here */
	{ 0, 0, NULL, 0 }		/* Dunno if needed, but just in case */
};

/*
 * More code to extract out the common name from an DER-encoded Name
 * field; we need this for dumping out things like a CKA_ISSUER when it
 * is passed down in FindObject search parameters
 *
 * A Name is a (ignoring first CHOICE, which is invisible to us):
 *
 * SEQUENCE OF RelativeDistinguisedNames
 *
 * RelativeDistinguishedNames are a SET OF ATVs (Attribute Type and Values)
 *
 * ATVs are a SEQUENCE { OID, VALUE } where VALUE is a CHOICE of String types.
 */

struct atv {
	SecAsn1Oid	oid;	/* AttributeType */
	SecAsn1Item	value;	/* AttributeValue */
};

struct rdn {
	struct atv	**atvs;	/* AttributeTypeAndValue */
};

struct name {
	struct rdn	**rdns;	/* RelativeDistinguishedName */
};

static const SecAsn1Template atv_template[] = {
	{ SEC_ASN1_SEQUENCE, 0, NULL, sizeof(struct atv) },
	{ SEC_ASN1_OBJECT_ID, offsetof(struct atv, oid), NULL, 0 },
	{ SEC_ASN1_ANY_CONTENTS, offsetof(struct atv, value), NULL, 0 },
	{ 0, 0, NULL, 0 },
};

static const SecAsn1Template rdn_template[] = {
	{ SEC_ASN1_SET_OF, offsetof(struct rdn, atvs), atv_template,
							sizeof(struct rdn) },
};

/*
 * We probably don't need the sizeof(struct name) at the end of this one,
 * but we included it in case we ever nest it in something else
 */

static const SecAsn1Template name_template[] = {
	{ SEC_ASN1_SEQUENCE_OF, offsetof(struct name, rdns), rdn_template,
						sizeof(struct name) },
};

/*
 * The encoded OID for a commonName
 */

static const unsigned char cn_oid[] = { 0x55, 0x04, 0x03 };	/* 2.5.4.3 */

/*
 * A decoding template to extract the modulus and public exponent from
 * RSAPublicKey encoded data.  Again, we don't need the size in the first
 * template marking the sequence, but we include it just in case we embed
 * that in something else later.
 *
 * A RSAPublicKey is a SEQUENCE of
 *
 * INTEGER (modulus)
 * INTEGER (publicExponent)
 */

struct rsa_pubkey {
	SecAsn1Item	modulus;
	SecAsn1Item	public_exponent;
};

static const SecAsn1Template rsapubkey_template[] = {
	{ SEC_ASN1_SEQUENCE, 0, NULL, sizeof(struct rsa_pubkey) },
	{ SEC_ASN1_INTEGER, offsetof(struct rsa_pubkey, modulus), NULL, 0 },
	{ SEC_ASN1_INTEGER, offsetof(struct rsa_pubkey, public_exponent),
								NULL, 0 },
	{ 0, 0, NULL, 0 },
};

/*
 * Extract out the DER-encoded certificate subject
 */

bool
get_certificate_info(CFDataRef certdata, CFDataRef *serialnumber,
		     CFDataRef *issuer, CFDataRef *subject)
{
	SecAsn1CoderRef coder;
	struct certinfo cinfo;
	OSStatus ret;

	/*
	 * We have to allocate a SecAsn1CoderRef before we call the decoder
	 * function; when we free it, it will release all of the allocated
	 * memory from the ASN.1 decoder, so make sure we copied everything.
	 */

	ret = SecAsn1CoderCreate(&coder);

	if (ret) {
		LOG_SEC_ERR("SecAsn1CreateCoder failed: %{public}@", ret);
		return false;
	}

	memset(&cinfo, 0, sizeof(cinfo));

	/*
	 * Perform the actual decoding, based on our template.  The
	 * DER bytes should end up in our cinfo structure.
	 */

	ret = SecAsn1Decode(coder, CFDataGetBytePtr(certdata),
			    CFDataGetLength(certdata), cert_template, &cinfo);

	if (ret) {
		SecAsn1CoderRelease(coder);
		LOG_SEC_ERR("SecAsn1Decode failed: %{public}@", ret);
		return false;
	}

	/*
	 * Looks like it all worked!  Return those in CFData structures
	 */

	*serialnumber = CFDataCreate(kCFAllocatorDefault,
				     cinfo.serialnumber.Data,
				     cinfo.serialnumber.Length);
	*issuer = CFDataCreate(kCFAllocatorDefault, cinfo.issuer.Data,
			       cinfo.issuer.Length);
	*subject = CFDataCreate(kCFAllocatorDefault, cinfo.subject.Data,
				cinfo.subject.Length);

	SecAsn1CoderRelease(coder);

	return true;
}

/*
 * Find the commonName out of a full DER-encoded Name
 */

char *
get_common_name(unsigned char *name, unsigned int namelen)
{
	SecAsn1CoderRef coder = NULL;
	struct name cname;
	OSStatus ret;
	int i, j;
	char *str;

	ret = SecAsn1CoderCreate(&coder);

	if (ret) {
		LOG_SEC_ERR("SecAsn1CreateCoder failed: %{public}@", ret);
		str = strdup("Unknown Name");
		goto out;
	}

	memset(&cname, 0, sizeof(cname));

	ret = SecAsn1Decode(coder, name, namelen, name_template, &cname);

	if (ret) {
		LOG_SEC_ERR("SecAsn1Decode failed: %{public}@", ret);
		str = strdup("Unparsable Name");
		goto out;
	}

	/*
	 * Look through each rdns/atv for the first common name we find
	 */

	for (i = 0; cname.rdns[i] != NULL; i++) {
		struct rdn *rdn = cname.rdns[i];

		for (j = 0; rdn->atvs[j] != NULL; j++) {
			struct atv *atv = rdn->atvs[j];

			if (atv->oid.Length == sizeof(cn_oid) &&
			    memcmp(atv->oid.Data, cn_oid,
				   sizeof(cn_oid)) == 0) {
				/*
				 * A match!
				 */

				size_t len = atv->value.Length;

				str = malloc(len + 1);

				strncpy(str, (char *) atv->value.Data, len);
				str[len] = '\0';
				goto out;
			}
		}
	}

	str = strdup("No Common Name Found");

out:
	if (coder)
		SecAsn1CoderRelease(coder);

	return str;
}

/*
 * Extract out the modulus and public exponent from a RSAPublicKey
 */

bool
get_pubkey_info(CFDataRef pubkeydata, CFDataRef *modulus, CFDataRef *exponent)
{
	SecAsn1CoderRef coder = NULL;
	struct rsa_pubkey pubkey;
	OSStatus ret;

	ret = SecAsn1CoderCreate(&coder);

	if (ret) {
		LOG_SEC_ERR("SecAsn1CreateCoder failed: %{public}@", ret);
		return false;
	}

	memset(&pubkey, 0, sizeof(pubkey));

	ret = SecAsn1Decode(coder, CFDataGetBytePtr(pubkeydata),
			    CFDataGetLength(pubkeydata),
			    rsapubkey_template, &pubkey);

	if (ret) {
		SecAsn1CoderRelease(coder);
		LOG_SEC_ERR("SecAsn1Decode failed: %{public}@", ret);
		return false;
	}

	/*
	 * Looks like it all worked!  Return those in CFData structures
	 */

	*modulus = CFDataCreate(kCFAllocatorDefault, pubkey.modulus.Data,
				pubkey.modulus.Length);

	*exponent = CFDataCreate(kCFAllocatorDefault,
				 pubkey.public_exponent.Data,
				 pubkey.public_exponent.Length);

	SecAsn1CoderRelease(coder);

	return true;
}

/*
 * Calculate the specified digest.  Sigh.  This SecTransform API is really
 * more complicated than I would want.
 */

CFDataRef
get_hash(CFTypeRef digest, CFIndex size, CFDataRef input)
{
	SecTransformRef tr;
	CFErrorRef err = NULL;
	CFDataRef result = NULL;

	tr = SecDigestTransformCreate(digest, size, &err);

	if (! tr) {
		os_log_debug(logsys, "SecDigestTransformCreate failed: "
			     "%{public}@", err);
		goto out;
	}

	if (!SecTransformSetAttribute(tr, kSecTransformInputAttributeName,
				      input, &err)) {
		os_log_debug(logsys, "SetTransformSetAttribute failed: "
			     "%{public}@", err);
		goto out;
	}

	result = SecTransformExecute(tr, &err);

	if (! result)
		os_log_debug(logsys, "SecTransformExecute failed: %{public}@",
			     err);

out:
	if (err)
		CFRelease(err);
	if (tr)
		CFRelease(tr);

	return result;
}
