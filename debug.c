/*
 *  debug.c
 *  KeychainToken
 *
 *  Created by Jay Kline on 7/1/09.
 *  Copyright 2009,2016
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include "debug.h"


char *hexify(unsigned char *data, int len) {
    char *s;
    int i;
    char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    s = (char *)malloc(len * 2 + 1);
    if (!s) return(NULL);
    memset(s, 0, len * 2 + 1);

    for  (i=0; i<len; i++) {
        s[i*2] = hexDigits[(data[i] >> 4) & 0x0f];
        s[i*2 + 1] = hexDigits[data[i] & 0x0f];
    }
    return(s);
}

char *stringify(unsigned char *str, int length) {
    static char my_string[128];

    if (length >= 128) return(NULL);
    memset(my_string, 0, sizeof(my_string));
    memcpy(my_string, str, length);
    my_string[length] = 0;
    return(my_string);
}

#define CS(name) case name: return #name

const char * getCKMName(CK_MECHANISM_TYPE mech) {
    switch (mech) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN: return "CKM_RSA_PKCS_KEY_PAIR_GEN";
        case CKM_RSA_PKCS: return "CKM_RSA_PKCS";
        case CKM_RSA_9796: return "CKM_RSA_9796";
        case CKM_RSA_X_509: return "CKM_RSA_X_509";
        case CKM_MD2_RSA_PKCS: return "CKM_MD2_RSA_PKCS";
        case CKM_MD5_RSA_PKCS: return "CKM_MD5_RSA_PKCS";
        case CKM_SHA1_RSA_PKCS: return "CKM_SHA1_RSA_PKCS";
        case CKM_RIPEMD128_RSA_PKCS: return "CKM_RIPEMD128_RSA_PKCS";
        case CKM_RIPEMD160_RSA_PKCS: return "CKM_RIPEMD160_RSA_PKCS";
        case CKM_RSA_PKCS_OAEP: return "CKM_RSA_PKCS_OAEP";
        case CKM_RSA_X9_31_KEY_PAIR_GEN: return "CKM_RSA_X9_31_KEY_PAIR_GEN";
        case CKM_RSA_X9_31: return "CKM_RSA_X9_31";
        case CKM_SHA1_RSA_X9_31: return "CKM_SHA1_RSA_X9_31";
        case CKM_RSA_PKCS_PSS: return "CKM_RSA_PKCS_PSS";
        case CKM_SHA1_RSA_PKCS_PSS: return "CKM_SHA1_RSA_PKCS_PSS";
        case CKM_DSA_KEY_PAIR_GEN: return "CKM_DSA_KEY_PAIR_GEN";
        case CKM_DSA: return "CKM_DSA";
        case CKM_DSA_SHA1: return "CKM_DSA_SHA1";
        case CKM_DH_PKCS_KEY_PAIR_GEN: return "CKM_DH_PKCS_KEY_PAIR_GEN";
        case CKM_DH_PKCS_DERIVE: return "CKM_DH_PKCS_DERIVE";
        case CKM_X9_42_DH_KEY_PAIR_GEN: return "CKM_X9_42_DH_KEY_PAIR_GEN";
        case CKM_X9_42_DH_DERIVE: return "CKM_X9_42_DH_DERIVE";
        case CKM_X9_42_DH_HYBRID_DERIVE: return "CKM_X9_42_DH_HYBRID_DERIVE";
        case CKM_X9_42_MQV_DERIVE: return "CKM_X9_42_MQV_DERIVE";
        case CKM_SHA256_RSA_PKCS: return "CKM_SHA256_RSA_PKCS";
        case CKM_SHA384_RSA_PKCS: return "CKM_SHA384_RSA_PKCS";
        case CKM_SHA512_RSA_PKCS: return "CKM_SHA512_RSA_PKCS";
        case CKM_SHA256_RSA_PKCS_PSS: return "CKM_SHA256_RSA_PKCS_PSS";
        case CKM_SHA384_RSA_PKCS_PSS: return "CKM_SHA384_RSA_PKCS_PSS";
        case CKM_SHA512_RSA_PKCS_PSS: return "CKM_SHA512_RSA_PKCS_PSS";
        case CKM_SHA224_RSA_PKCS: return "CKM_SHA224_RSA_PKCS";
        case CKM_SHA224_RSA_PKCS_PSS: return "CKM_SHA224_RSA_PKCS_PSS";
        case CKM_RC2_KEY_GEN: return "CKM_RC2_KEY_GEN";
        case CKM_RC2_ECB: return "CKM_RC2_ECB";
        case CKM_RC2_CBC: return "CKM_RC2_CBC";
        case CKM_RC2_MAC: return "CKM_RC2_MAC";
        case CKM_RC2_MAC_GENERAL: return "CKM_RC2_MAC_GENERAL";
        case CKM_RC2_CBC_PAD: return "CKM_RC2_CBC_PAD";
        case CKM_RC4_KEY_GEN: return "CKM_RC4_KEY_GEN";
        case CKM_RC4: return "CKM_RC4";
        case CKM_DES_KEY_GEN: return "CKM_DES_KEY_GEN";
        case CKM_DES_ECB: return "CKM_DES_ECB";
        case CKM_DES_CBC: return "CKM_DES_CBC";
        case CKM_DES_MAC: return "CKM_DES_MAC";
        case CKM_DES_MAC_GENERAL: return "CKM_DES_MAC_GENERAL";
        case CKM_DES_CBC_PAD: return "CKM_DES_CBC_PAD";
        case CKM_DES2_KEY_GEN: return "CKM_DES2_KEY_GEN";
        case CKM_DES3_KEY_GEN: return "CKM_DES3_KEY_GEN";
        case CKM_DES3_ECB: return "CKM_DES3_ECB";
        case CKM_DES3_CBC: return "CKM_DES3_CBC";
        case CKM_DES3_MAC: return "CKM_DES3_MAC";
        case CKM_DES3_MAC_GENERAL: return "CKM_DES3_MAC_GENERAL";
        case CKM_DES3_CBC_PAD: return "CKM_DES3_CBC_PAD";
        case CKM_CDMF_KEY_GEN: return "CKM_CDMF_KEY_GEN";
        case CKM_CDMF_ECB: return "CKM_CDMF_ECB";
        case CKM_CDMF_CBC: return "CKM_CDMF_CBC";
        case CKM_CDMF_MAC: return "CKM_CDMF_MAC";
        case CKM_CDMF_MAC_GENERAL: return "CKM_CDMF_MAC_GENERAL";
        case CKM_CDMF_CBC_PAD: return "CKM_CDMF_CBC_PAD";
        case CKM_DES_OFB64: return "CKM_DES_OFB64";
        case CKM_DES_OFB8: return "CKM_DES_OFB8";
        case CKM_DES_CFB64: return "CKM_DES_CFB64";
        case CKM_DES_CFB8: return "CKM_DES_CFB8";
        case CKM_MD2: return "CKM_MD2";
        case CKM_MD2_HMAC: return "CKM_MD2_HMAC";
        case CKM_MD2_HMAC_GENERAL: return "CKM_MD2_HMAC_GENERAL";
        case CKM_MD5: return "CKM_MD5";
        case CKM_MD5_HMAC: return "CKM_MD5_HMAC";
        case CKM_MD5_HMAC_GENERAL: return "CKM_MD5_HMAC_GENERAL";
        case CKM_SHA_1: return "CKM_SHA_1";
        case CKM_SHA_1_HMAC: return "CKM_SHA_1_HMAC";
        case CKM_SHA_1_HMAC_GENERAL: return "CKM_SHA_1_HMAC_GENERAL";
        case CKM_RIPEMD128: return "CKM_RIPEMD128";
        case CKM_RIPEMD128_HMAC: return "CKM_RIPEMD128_HMAC";
        case CKM_RIPEMD128_HMAC_GENERAL: return "CKM_RIPEMD128_HMAC_GENERAL";
        case CKM_RIPEMD160: return "CKM_RIPEMD160";
        case CKM_RIPEMD160_HMAC: return "CKM_RIPEMD160_HMAC";
        case CKM_RIPEMD160_HMAC_GENERAL: return "CKM_RIPEMD160_HMAC_GENERAL";
        case CKM_SHA256: return "CKM_SHA256";
        case CKM_SHA256_HMAC: return "CKM_SHA256_HMAC";
        case CKM_SHA256_HMAC_GENERAL: return "CKM_SHA256_HMAC_GENERAL";
        case CKM_SHA224: return "CKM_SHA224";
        case CKM_SHA224_HMAC: return "CKM_SHA224_HMAC";
        case CKM_SHA224_HMAC_GENERAL: return "CKM_SHA224_HMAC_GENERAL";
        case CKM_SHA384: return "CKM_SHA384";
        case CKM_SHA384_HMAC: return "CKM_SHA384_HMAC";
        case CKM_SHA384_HMAC_GENERAL: return "CKM_SHA384_HMAC_GENERAL";
        case CKM_SHA512: return "CKM_SHA512";
        case CKM_SHA512_HMAC: return "CKM_SHA512_HMAC";
        case CKM_SHA512_HMAC_GENERAL: return "CKM_SHA512_HMAC_GENERAL";
        case CKM_SECURID_KEY_GEN: return "CKM_SECURID_KEY_GEN";
        case CKM_SECURID: return "CKM_SECURID";
        case CKM_HOTP_KEY_GEN: return "CKM_HOTP_KEY_GEN";
        case CKM_HOTP: return "CKM_HOTP";
        case CKM_ACTI: return "CKM_ACTI";
        case CKM_ACTI_KEY_GEN: return "CKM_ACTI_KEY_GEN";
        case CKM_CAST_KEY_GEN: return "CKM_CAST_KEY_GEN";
        case CKM_CAST_ECB: return "CKM_CAST_ECB";
        case CKM_CAST_CBC: return "CKM_CAST_CBC";
        case CKM_CAST_MAC: return "CKM_CAST_MAC";
        case CKM_CAST_MAC_GENERAL: return "CKM_CAST_MAC_GENERAL";
        case CKM_CAST_CBC_PAD: return "CKM_CAST_CBC_PAD";
        case CKM_CAST3_KEY_GEN: return "CKM_CAST3_KEY_GEN";
        case CKM_CAST3_ECB: return "CKM_CAST3_ECB";
        case CKM_CAST3_CBC: return "CKM_CAST3_CBC";
        case CKM_CAST3_MAC: return "CKM_CAST3_MAC";
        case CKM_CAST3_MAC_GENERAL: return "CKM_CAST3_MAC_GENERAL";
        case CKM_CAST3_CBC_PAD: return "CKM_CAST3_CBC_PAD";
        case CKM_CAST128_KEY_GEN: return "CKM_CAST128_KEY_GEN";
        case CKM_CAST128_ECB: return "CKM_CAST128_ECB";
        case CKM_CAST128_CBC: return "CKM_CAST128_CBC";
        case CKM_CAST128_MAC: return "CKM_CAST128_MAC";
        case CKM_CAST128_MAC_GENERAL: return "CKM_CAST128_MAC_GENERAL";
        case CKM_CAST128_CBC_PAD: return "CKM_CAST128_CBC_PAD";
        case CKM_RC5_KEY_GEN: return "CKM_RC5_KEY_GEN";
        case CKM_RC5_ECB: return "CKM_RC5_ECB";
        case CKM_RC5_CBC: return "CKM_RC5_CBC";
        case CKM_RC5_MAC: return "CKM_RC5_MAC";
        case CKM_RC5_MAC_GENERAL: return "CKM_RC5_MAC_GENERAL";
        case CKM_RC5_CBC_PAD: return "CKM_RC5_CBC_PAD";
        case CKM_IDEA_KEY_GEN: return "CKM_IDEA_KEY_GEN";
        case CKM_IDEA_ECB: return "CKM_IDEA_ECB";
        case CKM_IDEA_CBC: return "CKM_IDEA_CBC";
        case CKM_IDEA_MAC: return "CKM_IDEA_MAC";
        case CKM_IDEA_MAC_GENERAL: return "CKM_IDEA_MAC_GENERAL";
        case CKM_IDEA_CBC_PAD: return "CKM_IDEA_CBC_PAD";
        case CKM_GENERIC_SECRET_KEY_GEN: return "CKM_GENERIC_SECRET_KEY_GEN";
        case CKM_CONCATENATE_BASE_AND_KEY: return "CKM_CONCATENATE_BASE_AND_KEY";
        case CKM_CONCATENATE_BASE_AND_DATA: return "CKM_CONCATENATE_BASE_AND_DATA";
        case CKM_CONCATENATE_DATA_AND_BASE: return "CKM_CONCATENATE_DATA_AND_BASE";
        case CKM_XOR_BASE_AND_DATA: return "CKM_XOR_BASE_AND_DATA";
        case CKM_EXTRACT_KEY_FROM_KEY: return "CKM_EXTRACT_KEY_FROM_KEY";
        case CKM_SSL3_PRE_MASTER_KEY_GEN: return "CKM_SSL3_PRE_MASTER_KEY_GEN";
        case CKM_SSL3_MASTER_KEY_DERIVE: return "CKM_SSL3_MASTER_KEY_DERIVE";
        case CKM_SSL3_KEY_AND_MAC_DERIVE: return "CKM_SSL3_KEY_AND_MAC_DERIVE";
        case CKM_SSL3_MASTER_KEY_DERIVE_DH: return "CKM_SSL3_MASTER_KEY_DERIVE_DH";
        case CKM_TLS_PRE_MASTER_KEY_GEN: return "CKM_TLS_PRE_MASTER_KEY_GEN";
        case CKM_TLS_MASTER_KEY_DERIVE: return "CKM_TLS_MASTER_KEY_DERIVE";
        case CKM_TLS_KEY_AND_MAC_DERIVE: return "CKM_TLS_KEY_AND_MAC_DERIVE";
        case CKM_TLS_MASTER_KEY_DERIVE_DH: return "CKM_TLS_MASTER_KEY_DERIVE_DH";
        case CKM_TLS_PRF: return "CKM_TLS_PRF";
        case CKM_SSL3_MD5_MAC: return "CKM_SSL3_MD5_MAC";
        case CKM_SSL3_SHA1_MAC: return "CKM_SSL3_SHA1_MAC";
        case CKM_MD5_KEY_DERIVATION: return "CKM_MD5_KEY_DERIVATION";
        case CKM_MD2_KEY_DERIVATION: return "CKM_MD2_KEY_DERIVATION";
        case CKM_SHA1_KEY_DERIVATION: return "CKM_SHA1_KEY_DERIVATION";
        case CKM_SHA256_KEY_DERIVATION: return "CKM_SHA256_KEY_DERIVATION";
        case CKM_SHA384_KEY_DERIVATION: return "CKM_SHA384_KEY_DERIVATION";
        case CKM_SHA512_KEY_DERIVATION: return "CKM_SHA512_KEY_DERIVATION";
        case CKM_SHA224_KEY_DERIVATION: return "CKM_SHA224_KEY_DERIVATION";
        case CKM_PBE_MD2_DES_CBC: return "CKM_PBE_MD2_DES_CBC";
        case CKM_PBE_MD5_DES_CBC: return "CKM_PBE_MD5_DES_CBC";
        case CKM_PBE_MD5_CAST_CBC: return "CKM_PBE_MD5_CAST_CBC";
        case CKM_PBE_MD5_CAST3_CBC: return "CKM_PBE_MD5_CAST3_CBC";
        case CKM_PBE_MD5_CAST128_CBC: return "CKM_PBE_MD5_CAST128_CBC";
        case CKM_PBE_SHA1_CAST128_CBC: return "CKM_PBE_SHA1_CAST128_CBC";
        case CKM_PBE_SHA1_RC4_128: return "CKM_PBE_SHA1_RC4_128";
        case CKM_PBE_SHA1_RC4_40: return "CKM_PBE_SHA1_RC4_40";
        case CKM_PBE_SHA1_DES3_EDE_CBC: return "CKM_PBE_SHA1_DES3_EDE_CBC";
        case CKM_PBE_SHA1_DES2_EDE_CBC: return "CKM_PBE_SHA1_DES2_EDE_CBC";
        case CKM_PBE_SHA1_RC2_128_CBC: return "CKM_PBE_SHA1_RC2_128_CBC";
        case CKM_PBE_SHA1_RC2_40_CBC: return "CKM_PBE_SHA1_RC2_40_CBC";
        case CKM_PKCS5_PBKD2: return "CKM_PKCS5_PBKD2";
        case CKM_PBA_SHA1_WITH_SHA1_HMAC: return "CKM_PBA_SHA1_WITH_SHA1_HMAC";
        case CKM_WTLS_PRE_MASTER_KEY_GEN: return "CKM_WTLS_PRE_MASTER_KEY_GEN";
        case CKM_WTLS_MASTER_KEY_DERIVE: return "CKM_WTLS_MASTER_KEY_DERIVE";
        case CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC: return "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC";
        case CKM_WTLS_PRF: return "CKM_WTLS_PRF";
        case CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: return "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE";
        case CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE: return "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE";
        case CKM_KEY_WRAP_LYNKS: return "CKM_KEY_WRAP_LYNKS";
        case CKM_KEY_WRAP_SET_OAEP: return "CKM_KEY_WRAP_SET_OAEP";
        case CKM_CMS_SIG: return "CKM_CMS_SIG";
        case CKM_KIP_DERIVE	: return "CKM_KIP_DERIVE	";
        case CKM_KIP_WRAP	: return "CKM_KIP_WRAP	";
        case CKM_KIP_MAC	: return "CKM_KIP_MAC	";
        case CKM_CAMELLIA_KEY_GEN: return "CKM_CAMELLIA_KEY_GEN";
        case CKM_CAMELLIA_ECB: return "CKM_CAMELLIA_ECB";
        case CKM_CAMELLIA_CBC: return "CKM_CAMELLIA_CBC";
        case CKM_CAMELLIA_MAC: return "CKM_CAMELLIA_MAC";
        case CKM_CAMELLIA_MAC_GENERAL: return "CKM_CAMELLIA_MAC_GENERAL";
        case CKM_CAMELLIA_CBC_PAD: return "CKM_CAMELLIA_CBC_PAD";
        case CKM_CAMELLIA_ECB_ENCRYPT_DATA: return "CKM_CAMELLIA_ECB_ENCRYPT_DATA";
        case CKM_CAMELLIA_CBC_ENCRYPT_DATA: return "CKM_CAMELLIA_CBC_ENCRYPT_DATA";
        case CKM_CAMELLIA_CTR: return "CKM_CAMELLIA_CTR";
        case CKM_ARIA_KEY_GEN: return "CKM_ARIA_KEY_GEN";
        case CKM_ARIA_ECB: return "CKM_ARIA_ECB";
        case CKM_ARIA_CBC: return "CKM_ARIA_CBC";
        case CKM_ARIA_MAC: return "CKM_ARIA_MAC";
        case CKM_ARIA_MAC_GENERAL: return "CKM_ARIA_MAC_GENERAL";
        case CKM_ARIA_CBC_PAD: return "CKM_ARIA_CBC_PAD";
        case CKM_ARIA_ECB_ENCRYPT_DATA: return "CKM_ARIA_ECB_ENCRYPT_DATA";
        case CKM_ARIA_CBC_ENCRYPT_DATA: return "CKM_ARIA_CBC_ENCRYPT_DATA";
        case CKM_SKIPJACK_KEY_GEN: return "CKM_SKIPJACK_KEY_GEN";
        case CKM_SKIPJACK_ECB64: return "CKM_SKIPJACK_ECB64";
        case CKM_SKIPJACK_CBC64: return "CKM_SKIPJACK_CBC64";
        case CKM_SKIPJACK_OFB64: return "CKM_SKIPJACK_OFB64";
        case CKM_SKIPJACK_CFB64: return "CKM_SKIPJACK_CFB64";
        case CKM_SKIPJACK_CFB32: return "CKM_SKIPJACK_CFB32";
        case CKM_SKIPJACK_CFB16: return "CKM_SKIPJACK_CFB16";
        case CKM_SKIPJACK_CFB8: return "CKM_SKIPJACK_CFB8";
        case CKM_SKIPJACK_WRAP: return "CKM_SKIPJACK_WRAP";
        case CKM_SKIPJACK_PRIVATE_WRAP: return "CKM_SKIPJACK_PRIVATE_WRAP";
        case CKM_SKIPJACK_RELAYX: return "CKM_SKIPJACK_RELAYX";
        case CKM_KEA_KEY_PAIR_GEN: return "CKM_KEA_KEY_PAIR_GEN";
        case CKM_KEA_KEY_DERIVE: return "CKM_KEA_KEY_DERIVE";
        case CKM_FORTEZZA_TIMESTAMP: return "CKM_FORTEZZA_TIMESTAMP";
        case CKM_BATON_KEY_GEN: return "CKM_BATON_KEY_GEN";
        case CKM_BATON_ECB128: return "CKM_BATON_ECB128";
        case CKM_BATON_ECB96: return "CKM_BATON_ECB96";
        case CKM_BATON_CBC128: return "CKM_BATON_CBC128";
        case CKM_BATON_COUNTER: return "CKM_BATON_COUNTER";
        case CKM_BATON_SHUFFLE: return "CKM_BATON_SHUFFLE";
        case CKM_BATON_WRAP: return "CKM_BATON_WRAP";
        case CKM_ECDSA_KEY_PAIR_GEN: return "CKM_ECDSA_KEY_PAIR_GEN";
        case CKM_ECDSA: return "CKM_ECDSA";
        case CKM_ECDSA_SHA1: return "CKM_ECDSA_SHA1";
        case CKM_ECDH1_DERIVE: return "CKM_ECDH1_DERIVE";
        case CKM_ECDH1_COFACTOR_DERIVE: return "CKM_ECDH1_COFACTOR_DERIVE";
        case CKM_ECMQV_DERIVE: return "CKM_ECMQV_DERIVE";
        case CKM_JUNIPER_KEY_GEN: return "CKM_JUNIPER_KEY_GEN";
        case CKM_JUNIPER_ECB128: return "CKM_JUNIPER_ECB128";
        case CKM_JUNIPER_CBC128: return "CKM_JUNIPER_CBC128";
        case CKM_JUNIPER_COUNTER: return "CKM_JUNIPER_COUNTER";
        case CKM_JUNIPER_SHUFFLE: return "CKM_JUNIPER_SHUFFLE";
        case CKM_JUNIPER_WRAP: return "CKM_JUNIPER_WRAP";
        case CKM_FASTHASH: return "CKM_FASTHASH";
        case CKM_AES_KEY_GEN: return "CKM_AES_KEY_GEN";
        case CKM_AES_ECB: return "CKM_AES_ECB";
        case CKM_AES_CBC: return "CKM_AES_CBC";
        case CKM_AES_MAC: return "CKM_AES_MAC";
        case CKM_AES_MAC_GENERAL: return "CKM_AES_MAC_GENERAL";
        case CKM_AES_CBC_PAD: return "CKM_AES_CBC_PAD";
        case CKM_AES_CTR: return "CKM_AES_CTR";
        case CKM_BLOWFISH_KEY_GEN: return "CKM_BLOWFISH_KEY_GEN";
        case CKM_BLOWFISH_CBC: return "CKM_BLOWFISH_CBC";
        case CKM_TWOFISH_KEY_GEN: return "CKM_TWOFISH_KEY_GEN";
        case CKM_TWOFISH_CBC: return "CKM_TWOFISH_CBC";
        case CKM_DES_ECB_ENCRYPT_DATA: return "CKM_DES_ECB_ENCRYPT_DATA";
        case CKM_DES_CBC_ENCRYPT_DATA: return "CKM_DES_CBC_ENCRYPT_DATA";
        case CKM_DES3_ECB_ENCRYPT_DATA: return "CKM_DES3_ECB_ENCRYPT_DATA";
        case CKM_DES3_CBC_ENCRYPT_DATA: return "CKM_DES3_CBC_ENCRYPT_DATA";
        case CKM_AES_ECB_ENCRYPT_DATA: return "CKM_AES_ECB_ENCRYPT_DATA";
        case CKM_AES_CBC_ENCRYPT_DATA: return "CKM_AES_CBC_ENCRYPT_DATA";
        case CKM_DSA_PARAMETER_GEN: return "CKM_DSA_PARAMETER_GEN";
        case CKM_DH_PKCS_PARAMETER_GEN: return "CKM_DH_PKCS_PARAMETER_GEN";
        case CKM_X9_42_DH_PARAMETER_GEN: return "CKM_X9_42_DH_PARAMETER_GEN";
        case CKM_VENDOR_DEFINED: return "CKM_VENDOR_DEFINED";
            /** Netscape Specific **/
        case CKM_FAKE_RANDOM: return "CKM_FAKE_RANDOM";
        case CKM_INVALID_MECHANISM: return "CKM_INVALID_MECHANISM";
        case CKM_NSS: return "CKM_NSS";
        case CKM_NSS_AES_KEY_WRAP: return "CKM_NSS_AES_KEY_WRAP";
        case CKM_NSS_AES_KEY_WRAP_PAD: return "CKM_NSS_AES_KEY_WRAP_PAD";
        case CKM_NETSCAPE_PBE_SHA1_DES_CBC: return "CKM_NETSCAPE_PBE_SHA1_DES_CBC";
        case CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC: return "CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC";
        case CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC: return "CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC";
        case CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC: return "CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC";
        case CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4: return "CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4";
        case CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4: return "CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4";
        case CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC: return "CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC";
        case CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN: return "CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN";
        case CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN: return "CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN";
        case CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN: return "CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN";
        case CKM_TLS_PRF_GENERAL: return "CKM_TLS_PRF_GENERAL";

        default:
            return "Unknown Key Type";
    }
}

const char * getCKAName(CK_ATTRIBUTE_TYPE attrib) {
    switch (attrib) {
        case CKA_CLASS: return "CKA_CLASS";
        case CKA_TOKEN: return "CKA_TOKEN";
        case CKA_PRIVATE: return "CKA_PRIVATE";
        case CKA_LABEL: return "CKA_LABEL";
        case CKA_APPLICATION: return "CKA_APPLICATION";
        case CKA_VALUE: return "CKA_VALUE";
        case CKA_OBJECT_ID: return "CKA_OBJECT_ID";
        case CKA_CERTIFICATE_TYPE: return "CKA_CERTIFICATE_TYPE";
        case CKA_ISSUER: return "CKA_ISSUER";
        case CKA_SERIAL_NUMBER: return "CKA_SERIAL_NUMBER";
        case CKA_AC_ISSUER: return "CKA_AC_ISSUER";
        case CKA_OWNER: return "CKA_OWNER";
        case CKA_ATTR_TYPES: return "CKA_ATTR_TYPES";
        case CKA_TRUSTED: return "CKA_TRUSTED";
        case CKA_CERTIFICATE_CATEGORY: return "CKA_CERTIFICATE_CATEGORY";
        case CKA_JAVA_MIDP_SECURITY_DOMAIN: return "CKA_JAVA_MIDP_SECURITY_DOMAIN";
        case CKA_URL: return "CKA_URL";
        case CKA_HASH_OF_SUBJECT_PUBLIC_KEY: return "CKA_HASH_OF_SUBJECT_PUBLIC_KEY";
        case CKA_HASH_OF_ISSUER_PUBLIC_KEY: return "CKA_HASH_OF_ISSUER_PUBLIC_KEY";
        case CKA_CHECK_VALUE: return "CKA_CHECK_VALUE";
        case CKA_KEY_TYPE: return "CKA_KEY_TYPE";
        case CKA_SUBJECT: return "CKA_SUBJECT";
        case CKA_ID: return "CKA_ID";
        case CKA_SENSITIVE: return "CKA_SENSITIVE";
        case CKA_ENCRYPT: return "CKA_ENCRYPT";
        case CKA_DECRYPT: return "CKA_DECRYPT";
        case CKA_WRAP: return "CKA_WRAP";
        case CKA_UNWRAP: return "CKA_UNWRAP";
        case CKA_SIGN: return "CKA_SIGN";
        case CKA_SIGN_RECOVER: return "CKA_SIGN_RECOVER";
        case CKA_VERIFY: return "CKA_VERIFY";
        case CKA_VERIFY_RECOVER: return "CKA_VERIFY_RECOVER";
        case CKA_DERIVE: return "CKA_DERIVE";
        case CKA_START_DATE: return "CKA_START_DATE";
        case CKA_END_DATE: return "CKA_END_DATE";
        case CKA_MODULUS: return "CKA_MODULUS";
        case CKA_MODULUS_BITS: return "CKA_MODULUS_BITS";
        case CKA_PUBLIC_EXPONENT: return "CKA_PUBLIC_EXPONENT";
        case CKA_PRIVATE_EXPONENT: return "CKA_PRIVATE_EXPONENT";
        case CKA_PRIME_1: return "CKA_PRIME_1";
        case CKA_PRIME_2: return "CKA_PRIME_2";
        case CKA_EXPONENT_1: return "CKA_EXPONENT_1";
        case CKA_EXPONENT_2: return "CKA_EXPONENT_2";
        case CKA_COEFFICIENT: return "CKA_COEFFICIENT";
        case CKA_PRIME: return "CKA_PRIME";
        case CKA_SUBPRIME: return "CKA_SUBPRIME";
        case CKA_BASE: return "CKA_BASE";
        case CKA_PRIME_BITS: return "CKA_PRIME_BITS";
        case CKA_SUBPRIME_BITS: return "CKA_SUBPRIME_BITS";
        case CKA_VALUE_BITS: return "CKA_VALUE_BITS";
        case CKA_VALUE_LEN: return "CKA_VALUE_LEN";
        case CKA_EXTRACTABLE: return "CKA_EXTRACTABLE";
        case CKA_LOCAL: return "CKA_LOCAL";
        case CKA_NEVER_EXTRACTABLE: return "CKA_NEVER_EXTRACTABLE";
        case CKA_ALWAYS_SENSITIVE: return "CKA_ALWAYS_SENSITIVE";
        case CKA_KEY_GEN_MECHANISM: return "CKA_KEY_GEN_MECHANISM";
        case CKA_MODIFIABLE: return "CKA_MODIFIABLE";
        case CKA_ECDSA_PARAMS: return "CKA_ECDSA_PARAMS";
        case CKA_EC_POINT: return "CKA_EC_POINT";
        case CKA_SECONDARY_AUTH: return "CKA_SECONDARY_AUTH";
        case CKA_AUTH_PIN_FLAGS: return "CKA_AUTH_PIN_FLAGS";
        case CKA_ALWAYS_AUTHENTICATE: return "CKA_ALWAYS_AUTHENTICATE";
        case CKA_WRAP_WITH_TRUSTED: return "CKA_WRAP_WITH_TRUSTED";
        case CKA_WRAP_TEMPLATE: return "CKA_WRAP_TEMPLATE";
        case CKA_UNWRAP_TEMPLATE: return "CKA_UNWRAP_TEMPLATE";
        case CKA_OTP_FORMAT: return "CKA_OTP_FORMAT";
        case CKA_OTP_LENGTH: return "CKA_OTP_LENGTH";
        case CKA_OTP_TIME_INTERVAL: return "CKA_OTP_TIME_INTERVAL";
        case CKA_OTP_USER_FRIENDLY_MODE: return "CKA_OTP_USER_FRIENDLY_MODE";
        case CKA_OTP_CHALLENGE_REQUIREMENT: return "CKA_OTP_CHALLENGE_REQUIREMENT";
        case CKA_OTP_TIME_REQUIREMENT: return "CKA_OTP_TIME_REQUIREMENT";
        case CKA_OTP_COUNTER_REQUIREMENT: return "CKA_OTP_COUNTER_REQUIREMENT";
        case CKA_OTP_PIN_REQUIREMENT: return "CKA_OTP_PIN_REQUIREMENT";
        case CKA_OTP_COUNTER: return "CKA_OTP_COUNTER";
        case CKA_OTP_TIME: return "CKA_OTP_TIME";
        case CKA_OTP_USER_IDENTIFIER: return "CKA_OTP_USER_IDENTIFIER";
        case CKA_OTP_SERVICE_IDENTIFIER: return "CKA_OTP_SERVICE_IDENTIFIER";
        case CKA_OTP_SERVICE_LOGO: return "CKA_OTP_SERVICE_LOGO";
        case CKA_OTP_SERVICE_LOGO_TYPE: return "CKA_OTP_SERVICE_LOGO_TYPE";
        case CKA_HW_FEATURE_TYPE: return "CKA_HW_FEATURE_TYPE";
        case CKA_RESET_ON_INIT: return "CKA_RESET_ON_INIT";
        case CKA_HAS_RESET: return "CKA_HAS_RESET";
        case CKA_PIXEL_X: return "CKA_PIXEL_X";
        case CKA_PIXEL_Y: return "CKA_PIXEL_Y";
        case CKA_RESOLUTION: return "CKA_RESOLUTION";
        case CKA_CHAR_ROWS: return "CKA_CHAR_ROWS";
        case CKA_CHAR_COLUMNS: return "CKA_CHAR_COLUMNS";
        case CKA_COLOR: return "CKA_COLOR";
        case CKA_BITS_PER_PIXEL: return "CKA_BITS_PER_PIXEL";
        case CKA_CHAR_SETS: return "CKA_CHAR_SETS";
        case CKA_ENCODING_METHODS: return "CKA_ENCODING_METHODS";
        case CKA_MIME_TYPES: return "CKA_MIME_TYPES";
        case CKA_MECHANISM_TYPE: return "CKA_MECHANISM_TYPE";
        case CKA_REQUIRED_CMS_ATTRIBUTES: return "CKA_REQUIRED_CMS_ATTRIBUTES";
        case CKA_DEFAULT_CMS_ATTRIBUTES: return "CKA_DEFAULT_CMS_ATTRIBUTES";
        case CKA_SUPPORTED_CMS_ATTRIBUTES: return "CKA_SUPPORTED_CMS_ATTRIBUTES";
        case CKA_ALLOWED_MECHANISMS: return "CKA_ALLOWED_MECHANISMS";
        case CKA_VENDOR_DEFINED: return "CKA_VENDOR_DEFINED";
            /** Netscape Specific **/
        case CKA_DIGEST: return "CKA_DIGEST";
        case CKA_NSS: return "CKA_NSS";
        case CKA_NSS_URL: return "CKA_NSS_URL";
        case CKA_NSS_EMAIL: return "CKA_NSS_EMAIL";
        case CKA_NSS_SMIME_INFO: return "CKA_NSS_SMIME_INFO";
        case CKA_NSS_SMIME_TIMESTAMP: return "CKA_NSS_SMIME_TIMESTAMP";
        case CKA_NSS_PKCS8_SALT: return "CKA_NSS_PKCS8_SALT";
        case CKA_NSS_PASSWORD_CHECK: return "CKA_NSS_PASSWORD_CHECK";
        case CKA_NSS_EXPIRES: return "CKA_NSS_EXPIRES";
        case CKA_NSS_KRL: return "CKA_NSS_KRL";
        case CKA_NSS_PQG_COUNTER: return "CKA_NSS_PQG_COUNTER";
        case CKA_NSS_PQG_SEED: return "CKA_NSS_PQG_SEED";
        case CKA_NSS_PQG_H: return "CKA_NSS_PQG_H";
        case CKA_NSS_PQG_SEED_BITS: return "CKA_NSS_PQG_SEED_BITS";
        case CKA_NSS_MODULE_SPEC: return "CKA_NSS_MODULE_SPEC";
        case CKA_NSS_OVERRIDE_EXTENSIONS: return "CKA_NSS_OVERRIDE_EXTENSIONS";
        case CKA_TRUST: return "CKA_TRUST";
        case CKA_TRUST_DIGITAL_SIGNATURE: return "CKA_TRUST_DIGITAL_SIGNATURE";
        case CKA_TRUST_NON_REPUDIATION: return "CKA_TRUST_NON_REPUDIATION";
        case CKA_TRUST_KEY_ENCIPHERMENT: return "CKA_TRUST_KEY_ENCIPHERMENT";
        case CKA_TRUST_DATA_ENCIPHERMENT: return "CKA_TRUST_DATA_ENCIPHERMENT";
        case CKA_TRUST_KEY_AGREEMENT: return "CKA_TRUST_KEY_AGREEMENT";
        case CKA_TRUST_KEY_CERT_SIGN: return "CKA_TRUST_KEY_CERT_SIGN";
        case CKA_TRUST_CRL_SIGN: return "CKA_TRUST_CRL_SIGN";
        case CKA_TRUST_SERVER_AUTH: return "CKA_TRUST_SERVER_AUTH";
        case CKA_TRUST_CLIENT_AUTH: return "CKA_TRUST_CLIENT_AUTH";
        case CKA_TRUST_CODE_SIGNING: return "CKA_TRUST_CODE_SIGNING";
        case CKA_TRUST_EMAIL_PROTECTION: return "CKA_TRUST_EMAIL_PROTECTION";
        case CKA_TRUST_IPSEC_END_SYSTEM: return "CKA_TRUST_IPSEC_END_SYSTEM";
        case CKA_TRUST_IPSEC_TUNNEL: return "CKA_TRUST_IPSEC_TUNNEL";
        case CKA_TRUST_IPSEC_USER: return "CKA_TRUST_IPSEC_USER";
        case CKA_TRUST_TIME_STAMPING: return "CKA_TRUST_TIME_STAMPING";
        case CKA_TRUST_STEP_UP_APPROVED: return "CKA_TRUST_STEP_UP_APPROVED";
        case CKA_CERT_SHA1_HASH: return "CKA_CERT_SHA1_HASH";
        case CKA_CERT_MD5_HASH: return "CKA_CERT_MD5_HASH";
        case CKA_NETSCAPE_DB: return "CKA_NETSCAPE_DB";
        case CKA_NETSCAPE_TRUST: return "CKA_NETSCAPE_TRUST";

        default:
            return "Unknown Attribute Type";
    }
}

const char * getCKOName(CK_OBJECT_CLASS class) {
    switch (class) {
        case CKO_DATA: return "CKO_DATA";
        case CKO_CERTIFICATE: return "CKO_CERTIFICATE";
        case CKO_PUBLIC_KEY: return "CKO_PUBLIC_KEY";
        case CKO_PRIVATE_KEY: return "CKO_PRIVATE_KEY";
        case CKO_SECRET_KEY: return "CKO_SECRET_KEY";
        case CKO_HW_FEATURE: return "CKO_HW_FEATURE";
        case CKO_DOMAIN_PARAMETERS: return "CKO_DOMAIN_PARAMETERS";
        case CKO_MECHANISM: return "CKO_MECHANISM";
        case CKO_OTP_KEY: return "CKO_OTP_KEY";
        case CKO_VENDOR_DEFINED: return "CKO_VENDOR_DEFINED";
            /** Netscape Specific **/
        case CKO_NSS: return "CKO_NSS";
        case CKO_NSS_CRL: return "CKO_NSS_CRL";
        case CKO_NSS_SMIME: return "CKO_NSS_SMIME";
        case CKO_NSS_TRUST: return "CKO_NSS_TRUST";
        case CKO_NSS_BUILTIN_ROOT_LIST: return "CKO_NSS_BUILTIN_ROOT_LIST";
        case CKO_NSS_NEWSLOT: return "CKO_NSS_NEWSLOT";
        case CKO_NSS_DELSLOT: return "CKO_NSS_DELSLOT";

        default:
            return "Unknown Object Type";
    }
}

const char * getCKRName(CK_RV rv) {
    switch (rv) {
        case CKR_OK: return "CKR_OK";
        case CKR_CANCEL: return "CKR_CANCEL";
        case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
        case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
        case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
        case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
        case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
        case CKR_NO_EVENT: return "CKR_NO_EVENT";
        case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
        case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
        case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
        case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
        case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
        case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
        case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
        case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
        case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
        case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
        case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
        case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
        case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
        case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
        case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
        case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
        case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
        case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
        case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
        case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
        case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
        case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
        case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
        case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
        case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
        case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
        case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
        case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
        case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
        case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
        case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
        case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
        case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
        case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
        case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
        case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
        case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
        case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
        case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
        case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
        case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
        case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
        case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
        case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
        case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
        case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
        case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
        case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
        case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
        case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
        case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
        case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
        case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
        case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
        case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
        case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
        case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
        case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
        case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
        case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
        case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
        case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
        case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
        case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
        case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
        case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
        case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
        case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
        case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
        case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
        case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
        case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
        case CKR_NEW_PIN_MODE: return "CKR_NEW_PIN_MODE";
        case CKR_NEXT_OTP: return "CKR_NEXT_OTP";
        case CKR_FUNCTION_REJECTED: return "CKR_FUNCTION_REJECTED";
        case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";
           /** Netscape Specific **/
        case CKR_NSS: return "CKR_NSS";
        case CKR_NSS_CERTDB_FAILED: return "CKR_NSS_CERTDB_FAILED";
        case CKR_NSS_KEYDB_FAILED: return "CKR_NSS_KEYDB_FAILED";

        default:
            return "Unknown error code";
    }
}


const char * getCKCName(CK_CERTIFICATE_TYPE ctype) {
    switch (ctype) {
        case CKC_X_509: return "CKC_X_509";
        case CKC_X_509_ATTR_CERT: return "CKC_X_509_ATTR_CERT";
        case CKC_WTLS: return "CKC_WTLS";
        case CKC_VENDOR_DEFINED: return "CKC_VENDOR_DEFINED";
           /** Netscap Specific **/
        case CKC_NSS: return "CKC_NSS";
        default:
            return "Unknown Certificate Type";
    }
}

const char * getCKSName(CK_STATE state) {
    switch (state) {
	CS(CKS_RO_PUBLIC_SESSION);
	CS(CKS_RO_USER_FUNCTIONS);
	CS(CKS_RW_PUBLIC_SESSION);
	CS(CKS_RW_USER_FUNCTIONS);
	CS(CKS_RW_SO_FUNCTIONS);
	default:
	    return "Unknown State";
    }
}

#if 0
const char * getSecErrorName(int status) {

    switch (status) {
        case errSecNotAvailable: return "errSecNotAvailable";
        case errSecReadOnly: return "errSecReadOnly";
        case errSecAuthFailed: return "errSecAuthFailed";
        case errSecNoSuchKeychain: return "errSecNoSuchKeychain";
        case errSecInvalidKeychain: return "errSecInvalidKeychain";
        case errSecDuplicateKeychain: return "errSecDuplicateKeychain";
        case errSecDuplicateCallback: return "errSecDuplicateCallback";
        case errSecInvalidCallback: return "errSecInvalidCallback";
        case errSecDuplicateItem: return "errSecDuplicateItem";
        case errSecItemNotFound: return "errSecItemNotFound";
        case errSecBufferTooSmall: return "errSecBufferTooSmall";
        case errSecDataTooLarge: return "errSecDataTooLarge";
        case errSecNoSuchAttr: return "errSecNoSuchAttr";
        case errSecInvalidItemRef: return "errSecInvalidItemRef";
        case errSecInvalidSearchRef: return "errSecInvalidSearchRef";
        case errSecNoSuchClass: return "errSecNoSuchClass";
        case errSecNoDefaultKeychain: return "errSecNoDefaultKeychain";
        case errSecInteractionNotAllowed: return "errSecInteractionNotAllowed";
        case errSecReadOnlyAttr: return "errSecReadOnlyAttr";
        case errSecWrongSecVersion: return "errSecWrongSecVersion";
        case errSecKeySizeNotAllowed: return "errSecKeySizeNotAllowed";
        case errSecNoStorageModule: return "errSecNoStorageModule";
        case errSecNoCertificateModule: return "errSecNoCertificateModule";
        case errSecNoPolicyModule: return "errSecNoPolicyModule";
        case errSecInteractionRequired: return "errSecInteractionRequired";
        case errSecDataNotAvailable: return "errSecDataNotAvailable";
        case errSecDataNotModifiable: return "errSecDataNotModifiable";
        case errSecCreateChainFailed: return "errSecCreateChainFailed";
        case errSecInvalidPrefsDomain: return "errSecInvalidPrefsDomain";
        case errSecACLNotSimple: return "errSecACLNotSimple";
        case errSecPolicyNotFound: return "errSecPolicyNotFound";
        case errSecInvalidTrustSetting: return "errSecInvalidTrustSetting";
        case errSecNoAccessForItem: return "errSecNoAccessForItem";
        case errSecInvalidOwnerEdit: return "errSecInvalidOwnerEdit";
        case errSecTrustNotAvailable: return "errSecTrustNotAvailable";
        case errSecUnsupportedFormat: return "errSecUnsupportedFormat";
        case errSecUnknownFormat: return "errSecUnknownFormat";
        case errSecKeyIsSensitive: return "errSecKeyIsSensitive";
        case errSecMultiplePrivKeys: return "errSecMultiplePrivKeys";
        case errSecPassphraseRequired: return "errSecPassphraseRequired";
        case errSecInvalidPasswordRef: return "errSecInvalidPasswordRef";
        case errSecInvalidTrustSettings: return "errSecInvalidTrustSettings ";
        case errSecNoTrustSettings: return "errSecNoTrustSettings";
        case errSecPkcs12VerifyFailure: return "errSecPkcs12VerifyFailure ";
        default: return "";
    }
}
#endif

void
debug(int level, const char *format, ...) {
#ifdef DEBUG
    va_list args;

    if (level > DEBUG_LEVEL)
        return;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
#else
    /* empty */
#endif
}
