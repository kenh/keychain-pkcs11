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
	{ CKM_SHA1_RSA_PKCS, 1024, 8192, CKF_HW|CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
	  &kSecDigestSHA1, 0, true},
	{ CKM_SHA256_RSA_PKCS, 1024, 8192, CKF_HW|CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
	  &kSecDigestSHA2, 256, true },
	{ CKM_SHA384_RSA_PKCS, 1024, 8192, CKF_HW|CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
	  &kSecDigestSHA2, 384, true },
	{ CKM_SHA512_RSA_PKCS, 1024, 8192, CKF_HW|CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
	  &kSecDigestSHA2, 512, true },
};

unsigned int keychain_mechmap_size = sizeof(keychain_mechmap)/
						sizeof(keychain_mechmap[0]);

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
