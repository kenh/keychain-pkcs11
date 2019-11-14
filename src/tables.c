/*
 * Various tables we need for our crypto library to map between
 * Cryptoki constants and Security framework parameters
 */

#include <Security/Security.h>
#include "mypkcs11.h"
#include "tables.h"

struct mechanism_map keychain_mechmap[] = {
	{ CKM_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|CKF_VERIFY,
	  &kSecKeyAlgorithmRSAEncryptionPKCS1,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
	  NULL,		/* Again, special case */
	  NULL, 0	/* Special case - no digest algoritm specified */,
	  true },
	{ CKM_SHA1_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
	  &kSecDigestSHA1, 0, true},
	{ CKM_SHA256_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
	  &kSecDigestSHA2, 256, true },
	{ CKM_SHA384_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
	  &kSecDigestSHA2, 384, true },
	{ CKM_SHA512_RSA_PKCS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
	  &kSecDigestSHA2, 512, true },
	{ CKM_RSA_PKCS_OAEP, 1024, 8192,
	  CKF_HW|CKF_ENCRYPT|CKF_DECRYPT,
	  NULL,		/* Filled in by parameter function */
	  NULL,
	  NULL,
	  NULL, 0, true },
	{ CKM_RSA_PKCS_PSS, 1024, 8192,
	  CKF_HW|CKF_SIGN|CKF_VERIFY,
	  NULL,		/* Filled in by parameter function */
	  NULL,
	  NULL,
	  NULL, 0, true },
};

unsigned int keychain_mechmap_size = sizeof(keychain_mechmap)/
						sizeof(keychain_mechmap[0]);

/*
 * Mapping of parameter values to Security algorithms
 */

struct param_map keychain_param_map[] = {
	{ CKM_RSA_PKCS_OAEP,
	  CKM_SHA_1,
	  CKG_MGF1_SHA1,
	  0,
	  OAEP,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
	  NULL,
	},
	{ CKM_RSA_PKCS_OAEP,
	  CKM_SHA224,
	  CKG_MGF1_SHA224,
	  0,
	  OAEP,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
	  NULL,
	  },
	{ CKM_RSA_PKCS_OAEP,
	  CKM_SHA256,
	  CKG_MGF1_SHA256,
	  0,
	  OAEP,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
	  NULL,
	},
	{ CKM_RSA_PKCS_OAEP,
	  CKM_SHA384,
	  CKG_MGF1_SHA384,
	  0,
	  OAEP,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
	  NULL,
	},
	{ CKM_RSA_PKCS_OAEP,
	  CKM_SHA512,
	  CKG_MGF1_SHA512,
	  0,
	  OAEP,
	  &kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
	  NULL,
	},
	{ CKM_RSA_PKCS_PSS,
	  CKM_SHA_1,
	  CKG_MGF1_SHA1,
	  20,
	  PSS,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA1,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA1,
	},
	{ CKM_RSA_PKCS_PSS,
	  CKM_SHA224,
	  CKG_MGF1_SHA224,
	  28,
	  PSS,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA224,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA224,
	},
	{ CKM_RSA_PKCS_PSS,
	  CKM_SHA256,
	  CKG_MGF1_SHA256,
	  32,
	  PSS,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
	},
	{ CKM_RSA_PKCS_PSS,
	  CKM_SHA384,
	  CKG_MGF1_SHA384,
	  48,
	  PSS,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA384,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
	},
	{ CKM_RSA_PKCS_PSS,
	  CKM_SHA512,
	  CKG_MGF1_SHA512,
	  64,
	  PSS,
	  &kSecKeyAlgorithmRSASignatureMessagePSSSHA512,
	  &kSecKeyAlgorithmRSASignatureDigestPSSSHA512,
	},
};

/*
 * Mapping of Security framework constants to Cryptoki constants
 */

struct keymap keytype_map[] = {
        { "RSA Key", CKK_RSA, &kSecAttrKeyTypeRSA },
	{ "DSA Key", CKK_DSA, &kSecAttrKeyTypeDSA },
	{ "AES Key", CKK_AES, &kSecAttrKeyTypeAES },
	{ "DES Key", CKK_DES, &kSecAttrKeyTypeDES },
	{ "3DES Key", CKK_DES3, &kSecAttrKeyType3DES },
	{ "EC Key", CKK_EC, &kSecAttrKeyTypeEC },
	{ NULL, 0, NULL },
};
