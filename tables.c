/*
 * Various tables we need for our crypto library to map between
 * Cryptoki constants and Security framework parameters
 */

#include <Security/Security.h>
#include "mypkcs11.h"
#include "tables.h"

struct mechanism_map keychain_mechmap[] = {
	{ CKM_RSA_PKCS, 512, 8192, CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|CKF_VERIFY,
	  &kSecKeyAlgorithmRSAEncryptionPKCS1,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
	  NULL, 0	/* Special case - no digest algoritm specified */ },
	{ CKM_SHA1_RSA_PKCS, 512, 8192, CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
	  &kSecDigestSHA1, 0 },
	{ CKM_SHA256_RSA_PKCS, 512, 8192, CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
	  &kSecDigestSHA2, 256 },
	{ CKM_SHA384_RSA_PKCS, 512, 8192, CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
	  &kSecDigestSHA2, 384 },
	{ CKM_SHA512_RSA_PKCS, 512, 8192, CKF_SIGN|CKF_VERIFY,
	  NULL,
	  &kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
	  &kSecDigestSHA2, 512 },
};

unsigned int keychain_mechmap_size = sizeof(keychain_mechmap)/
						sizeof(keychain_mechmap[0]);
