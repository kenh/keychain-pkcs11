/*
 * Various tables we need for our crypto library to map between
 * Cryptoki constants and Security framework parameters
 */

#include <Security/Security.h>
#include "mypkcs11.h"
#include "tables.h"

/*
 * A special note on CKM_RSA_PKCS and CKM_RSA_X_509.
 *
 * These mechanisms are special in that they don't technically take
 * arbitrary user data; it has to be formatted properly.  As a result,
 * you shouldn't use these mechanisms unless you know exactly what you
 * are doing.
 *
 * For encryption, CKM_RSA_PKCS can mostly take arbitrary data up to
 * the key size (minus 11 bytes).  The data will be padded using
 * PKCS #1 v1.5 block type 2.  When decrypted the padding will be removed
 * and you will get back the original input buffer given during encryption.
 * But for signing the input is only padded with PKCS #1 v.1 block type 1;
 * an encoded DigestInfo structure is NOT generated.  So the input for
 * signing should be a properly encoded DigestInfo structure with the
 * appropriate digest algorithm OID and message.  For signature verification
 * things work the same way: the passed-in buffer should be an encoded
 * DigestInfo structure.
 *
 * CKM_RSA_X_509 is basically the "raw" RSA operations; the input buffer
 * is treated as most-sigificant-byte first integer and the appropriate
 * RSA operation is performed on this integer.  This can be used as a
 * building block for other RSA mechanisms, but should not be used directly
 * without some form of padding applied to the input buffer.
 */

const struct mechanism_map keychain_mechmap[] = {
	{
	  CKM_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|CKF_VERIFY, NONE,
	  &kSecKeyAlgorithmRSAEncryptionPKCS1,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
	  NULL, 0	/* Special case - no digest algoritm specified */,
	  true,
	},
	{
	  CKM_SHA1_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, NONE,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
	  CKM_SHA_1, true,
	},
	{
	  CKM_SHA224_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, NONE,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224,
	  CKM_SHA224, true,
	},
	{
	  CKM_SHA256_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, NONE,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
	  CKM_SHA256, true,
	},
	{
	  CKM_SHA384_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, NONE,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
	  CKM_SHA384, true,
	},
	{
	  CKM_SHA512_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, NONE,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
	  CKM_SHA512, true,
	},
	{
	  CKM_RSA_PKCS_OAEP, 1024, 8192,
	  CKF_HW|CKF_ENCRYPT|CKF_DECRYPT, OAEP,
	  NULL,		/* Filled in by parameter function */
	  NULL,
	  NULL,
	  0, true,
	},
	{
	  CKM_RSA_PKCS_PSS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, PSS,
	  NULL,		/* Filled in by parameter function */
	  NULL,
	  NULL,
	  0, true,
	},
	{
	  CKM_SHA1_RSA_PKCS_PSS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, PSS,
	  NULL,		/* Filled in by parameter function */
	  NULL,
	  NULL,
	  CKM_SHA_1, true,
	},
	{
	  CKM_SHA224_RSA_PKCS_PSS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, PSS,
	  NULL,		/* Filled in by parameter function */
	  NULL,
	  NULL,
	  CKM_SHA224, true,
	},
	{
	  CKM_SHA256_RSA_PKCS_PSS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, PSS,
	  NULL,		/* Filled in by parameter function */
	  NULL,
	  NULL,
	  CKM_SHA256, true,
	},
	{
	  CKM_SHA384_RSA_PKCS_PSS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, PSS,
	  NULL,		/* Filled in by parameter function */
	  NULL,
	  NULL,
	  CKM_SHA384, true,
	},
	{
	  CKM_SHA512_RSA_PKCS_PSS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY, PSS,
	  NULL,		/* Filled in by parameter function */
	  NULL,
	  NULL,
	  CKM_SHA512, true,
	},
	{
	  CKM_RSA_X_509, 1024, 8192,
	  CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|CKF_VERIFY, NONE,
	  &kSecKeyAlgorithmRSAEncryptionRaw,
	  &kSecKeyAlgorithmRSASignatureRaw,
	  /* &kSecKeyAlgorithmRSASignatureRaw, */
	  NULL, 0,	/* Another special case; no digest algorithm */
	  true,
	},
};

const unsigned int keychain_mechmap_size = sizeof(keychain_mechmap) /
						sizeof(keychain_mechmap[0]);

/*
 * Mapping of parameter values to Security algorithms
 */

const struct param_map keychain_param_map[] = {
	{
	  CKM_RSA_PKCS_OAEP,
	  CKM_SHA_1,
	  CKG_MGF1_SHA1,
	  0,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
	  NULL,
	  NULL,
	},
	{
	  CKM_RSA_PKCS_OAEP,
	  CKM_SHA224,
	  CKG_MGF1_SHA224,
	  0,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
	  NULL,
	  NULL,
	},
	{
	  CKM_RSA_PKCS_OAEP,
	  CKM_SHA256,
	  CKG_MGF1_SHA256,
	  0,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
	  NULL,
	  NULL,
	},
	{
	  CKM_RSA_PKCS_OAEP,
	  CKM_SHA384,
	  CKG_MGF1_SHA384,
	  0,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
	  NULL,
	  NULL,
	},
	{
	  CKM_RSA_PKCS_OAEP,
	  CKM_SHA512,
	  CKG_MGF1_SHA512,
	  0,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
	  NULL,
	  NULL,
	},
	{
	  CKM_RSA_PKCS_PSS,
	  CKM_SHA_1,
	  CKG_MGF1_SHA1,
	  20,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA1,
	  NULL,
	},
	{
	  CKM_RSA_PKCS_PSS,
	  CKM_SHA224,
	  CKG_MGF1_SHA224,
	  28,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA224,
	  NULL,
	},
	{
	  CKM_RSA_PKCS_PSS,
	  CKM_SHA256,
	  CKG_MGF1_SHA256,
	  32,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
	  NULL,
	},
	{
	  CKM_RSA_PKCS_PSS,
	  CKM_SHA384,
	  CKG_MGF1_SHA384,
	  48,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
	  NULL,
	},
	{
	  CKM_RSA_PKCS_PSS,
	  CKM_SHA512,
	  CKG_MGF1_SHA512,
	  64,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA512,
	  NULL,
	},
	{
	  CKM_SHA1_RSA_PKCS_PSS,
	  CKM_SHA_1,
	  CKG_MGF1_SHA1,
	  20,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA1,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA1,
	},
	{
	  CKM_SHA224_RSA_PKCS_PSS,
	  CKM_SHA224,
	  CKG_MGF1_SHA224,
	  28,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA224,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA224,
	},
	{
	  CKM_SHA256_RSA_PKCS_PSS,
	  CKM_SHA256,
	  CKG_MGF1_SHA256,
	  32,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
	},
	{
	  CKM_SHA384_RSA_PKCS_PSS,
	  CKM_SHA384,
	  CKG_MGF1_SHA384,
	  48,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA384,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
	},
	{
	  CKM_SHA512_RSA_PKCS_PSS,
	  CKM_SHA512,
	  CKG_MGF1_SHA512,
	  64,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA512,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA512,
	},
};

const unsigned int keychain_param_map_size = sizeof(keychain_param_map) /
					sizeof(keychain_param_map[0]);

/*
 * Mapping of Security framework constants to Cryptoki constants
 */

const struct keymap keytype_map[] = {
        { "RSA Key", CKK_RSA, &kSecAttrKeyTypeRSA },
	{ "DSA Key", CKK_DSA, &kSecAttrKeyTypeDSA },
	{ "AES Key", CKK_AES, &kSecAttrKeyTypeAES },
	{ "DES Key", CKK_DES, &kSecAttrKeyTypeDES },
	{ "3DES Key", CKK_DES3, &kSecAttrKeyType3DES },
	{ "EC Key", CKK_EC, &kSecAttrKeyTypeEC },
	{ NULL, 0, NULL },
};
