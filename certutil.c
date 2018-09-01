/*
 * Utility routines for dealing with various things about certificates
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>

#include "certutil.h"
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
 * Extract out the DER-encoded certificate subject
 */

bool
get_certificate_info(CFDataRef certdata, CFDataRef *issuer, CFDataRef *subject)
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

	if (ret)
		return false;

	memset(&cinfo, 0, sizeof(cinfo));

	/*
	 * Perform the actual decoding, based on our template.  The
	 * DER bytes should end up in our cinfo structure.
	 */

	ret = SecAsn1Decode(coder, CFDataGetBytePtr(certdata),
			    CFDataGetLength(certdata), cert_template, &cinfo);

	if (ret) {
		SecAsn1CoderRelease(coder);
		return false;
	}

	/*
	 * Looks like it all worked!  Return those in CFData structures
	 */

	*issuer = CFDataCreate(kCFAllocatorDefault, cinfo.issuer.Data,
			       cinfo.issuer.Length);
	*subject = CFDataCreate(kCFAllocatorDefault, cinfo.subject.Data,
				cinfo.subject.Length);

	SecAsn1CoderRelease(coder);

	return true;
}
