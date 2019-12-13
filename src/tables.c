/*
 * Various tables we need for our crypto library to map between
 * Cryptoki constants and Security framework parameters
 */

#include <Security/Security.h>
#include "mypkcs11.h"
#include "tables.h"

const struct mechanism_map keychain_mechmap[] = {
	{
	  CKM_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|CKF_VERIFY, NONE,
	  &kSecKeyAlgorithmRSAEncryptionPKCS1,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
	  NULL,		/* Again, special case */
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
