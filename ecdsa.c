#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>


#define curve_name NID_secp224r1

typedef struct _myCert_ {
  const char* owner;
  char  pub_key[57*2 + 1];
  char* priv_key;
  char  signature[128 + 1];
} myCert;

int create_keys(char** pub_hex, char** priv_hex);
int bytes_to_hex(unsigned char* bytes, int der_len, char** hex_str);
int hex_to_bytes(char* hex, unsigned char** bytes);
int verify_signature(unsigned char* hash, char* signature, char* pub_key);
int sign(unsigned char* hash, char* priv_hex, char** sig_hex);
int hash_mycert(myCert* cert, unsigned char** hash);
int sign_mycert(myCert* cert, char* private_key);
int verify_mycert(myCert* cert, char* pub_key);
int create_new_cert(const char* owner, myCert** cert);
void print_mycert(myCert* cert);

int main(int argc, char* argv[])
{
  char *sig = NULL, *pub_key = NULL, *priv_key = NULL;
  int verify_res;
  myCert cert;
  myCert *cert_ptr = &cert;

  create_keys(&pub_key, &priv_key);
  printf("Public key : %s\nPrivate key: %s\n", pub_key, priv_key);
  sign((unsigned char*)"this is the second hash", priv_key, &sig);
  printf("Signature: %s\n", sig);
  verify_res = verify_signature((unsigned char*)"this is the second hash", sig, pub_key);
  printf("Verification result: %s\n", verify_res ? "SUCCESS" : "FAIL");
  printf("Signature length  : %d\n", (int)strlen(sig));
  printf("Private key length: %d\n", (int)strlen(priv_key));
  printf("Public key length : %d\n", (int)strlen(pub_key));

  create_new_cert("Alexander Wachter", &cert_ptr);
  sign_mycert(cert_ptr, priv_key);
  print_mycert(cert_ptr);
  verify_res = verify_mycert(cert_ptr, pub_key);
  printf("Certificate verification result: %s\n", verify_res ? "SUCCESS" : "FAIL");
  free(pub_key);
  free(priv_key);
  free(cert.priv_key);

  return EXIT_SUCCESS;
}

int create_new_cert(const char* owner, myCert** cert)
{
  myCert* cert_;
  char* pub_key = NULL;
  char* priv_key = NULL;

  if(NULL == *cert)
  {
    *cert = malloc(sizeof(myCert));
    if(*cert == NULL)
      return 0;
  }
  cert_ = *cert;

  cert_->owner = owner;
  if(!create_keys(&pub_key, &priv_key))
    return 0;
  strcpy(cert_->pub_key, pub_key);
  cert_->priv_key = priv_key;
  cert_->signature[0] = '\0';
  return 1;
}

void print_mycert(myCert* cert)
{
  printf("Mycert:\nOwner: %s\nPublic key : %s\nPrivate key: %s\nSignature  : %s\n", 
         cert->owner, cert->pub_key, cert->priv_key ? cert->priv_key : "Not set", cert->signature);
}

int sign_mycert(myCert* cert, char* sign_priv_key)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned char *hash_ptr = hash;
  char* signature = cert->signature;

  if(!hash_mycert(cert, &hash_ptr))
    return 0;
  if(!sign(hash, sign_priv_key, &signature))
    return 0;
  return 1;
}

int verify_mycert(myCert* cert, char* pub_key)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned char *hash_ptr = hash;

  if(!hash_mycert(cert, &hash_ptr))
    return 0;
  return verify_signature(hash, cert->signature, pub_key);
}

int hash_mycert(myCert* cert, unsigned char** hash)
{
  SHA256_CTX sha256_ctx;

  if(NULL == *hash)
  {
    *hash = malloc(SHA256_DIGEST_LENGTH);
    if(*hash == NULL)
      return 0;
  }

  if(!SHA256_Init(&sha256_ctx))
    return -1;

  SHA256_Update(&sha256_ctx, cert->owner, strlen(cert->owner));
  SHA256_Update(&sha256_ctx, cert->pub_key, strlen(cert->pub_key));
  if(!SHA256_Final(*hash, &sha256_ctx))
    return 0;

  return 1;
}

int hex_to_bytes(char* hex, unsigned char** bytes)
{
  int len, i;
  char *hex_ptr, val, digit_val;
  unsigned char *bytes_ptr;
  unsigned char alloc = 0;

  if(!hex)
    return 0;
  len = strlen(hex);
  if(NULL == *bytes)
  {
    alloc = 1;
    *bytes = malloc(len * sizeof(char) / 2);
    if(!*bytes)
      return 0;
  }
  bytes_ptr = *bytes;
  hex_ptr = hex;
  for(i = 0; i < len / 2; i++)
  {
    digit_val = *(hex_ptr++);
    if( !((digit_val >= '0' && digit_val <= '9') || (digit_val >= 'A' && digit_val <= 'F')))
    {
      if(alloc)
        free(bytes_ptr);
      return 0;
    }
    digit_val = digit_val > '9' ? digit_val - 'A' + 10 : digit_val - '0';
    val = digit_val * 16;
    digit_val = *(hex_ptr++);
    if( !((digit_val >= '0' && digit_val <= '9') || (digit_val >= 'A' && digit_val <= 'F')))
    {
      if(alloc)
        free(bytes_ptr);
      return 0;
    }
    digit_val = digit_val > '9' ? digit_val - 'A' + 10 : digit_val - '0';
    val += digit_val;
    bytes_ptr[i] = val;
  }
  return len/2;
}

int bytes_to_hex(unsigned char* bytes, int len, char** hex_str)
{
  int i;
  char *str_ptr, val, val_digit;
  int str_size = len * sizeof(char) * 2;

  if(NULL == *hex_str)
  {
    *hex_str = malloc(str_size + 1);
    if(NULL == *hex_str)
      return 0;
  }

  str_ptr = *hex_str;
  for(i = 0; i < len; i++)
  {
    val = bytes[i];
    val_digit = (val & 0xF0) >> 4;
    *(str_ptr++) = val_digit < 10 ? val_digit + '0' : val_digit - 10 + 'A';
    val_digit = val & 0x0F;
    *(str_ptr++) = val_digit < 10 ? val_digit + '0' : val_digit - 10 + 'A';
  }
  *str_ptr = '\0';
  return 1;
}

int verify_signature(unsigned char* hash, char* signature, char* pub_key)
{
  EC_KEY   *eckey    = NULL;
  EC_GROUP *ecgroup  = NULL;
  EC_POINT* pub      = NULL;
  BN_CTX *bnctx      = NULL;
  ECDSA_SIG *sig     = NULL;
  unsigned char* der = NULL;
  int der_len;
  unsigned long err;
  int ret = 0;

  if (NULL == (bnctx = BN_CTX_new()))
  {
    printf("Failed to generate bignum context\n");
    goto ecc_ver_error;
  }

  if (NULL == (eckey = EC_KEY_new()))
  {
    printf("Failed to create new EC Key\n");
    goto ecc_ver_error;
  }
  if (NULL == (ecgroup = EC_GROUP_new_by_curve_name(curve_name)))
  {
    printf("Failed to create new EC Group\n");
    goto ecc_ver_error;
  }
  if (1 != EC_KEY_set_group(eckey,ecgroup))
  {
    printf("Failed to set group for EC Key\n");
    goto ecc_ver_error;
  }
  if(NULL == (pub = (EC_POINT_hex2point(ecgroup, pub_key, pub, bnctx))))
  {
    printf("Failed to read the public key\n");
    goto ecc_ver_error;
  }
  if (!EC_KEY_set_public_key(eckey, pub))
  {
    printf("Failed to set pub key\n");
    goto ecc_ver_error;
  }
  if(! (der_len = hex_to_bytes(signature, &der)))
  {
    printf("Failed to create DER from signature\n");
    goto ecc_ver_error;
  }
  const unsigned char* der_copy = der;
  if(!(sig = d2i_ECDSA_SIG(NULL, &der_copy, der_len)))
  {
    printf("Failed to create signature from DER\n");
    goto ecc_ver_error;
  }

  ret = ECDSA_do_verify(hash, strlen((char*)hash), sig, eckey);

ecc_ver_error:
  if((err = ERR_get_error()))
    printf("SSL ERROR: %s\n",ERR_error_string(err, NULL));
  BN_CTX_free(bnctx);
  EC_GROUP_free(ecgroup);
  EC_KEY_free(eckey);
  EC_POINT_free(pub);
  free(der);
  free(sig);
  return ret;
}

int sign(unsigned char* hash, char* priv_hex, char** sig_hex)
{
  EC_KEY   *eckey    = NULL;
  EC_GROUP *ecgroup  = NULL;
  EC_POINT* pub      = NULL;
  BIGNUM *priv       = NULL;
  BN_CTX *bnctx      = NULL;
  ECDSA_SIG *sig     = NULL;
  unsigned char* der = NULL;
  int der_len;
  unsigned long err;
  int ret = 0;

  if (NULL == (bnctx = BN_CTX_new()))
  {
    printf("Failed to generate bignum context\n");
    goto ecc_sig_error;
  }
  if (NULL == (eckey = EC_KEY_new()))
  {
    printf("Failed to create new EC Key\n");
    goto ecc_sig_error;
  }
  if (NULL == (ecgroup = EC_GROUP_new_by_curve_name(curve_name)))
  {
    printf("Failed to create new EC Group\n");
    goto ecc_sig_error;
  }
  if (1 != EC_KEY_set_group(eckey,ecgroup))
  {
    printf("Failed to set group for EC Key\n");
    goto ecc_sig_error;
  }
  if(NULL == (pub = EC_POINT_new(ecgroup)))
  {
    printf("Failed to create public key\n");
    goto ecc_sig_error;
  }
  if (!BN_hex2bn(&priv, priv_hex))
  {
    printf("Failed to read private key hex\n");
    goto ecc_sig_error;
  }
  if(1 != EC_KEY_set_private_key(eckey, priv))
  {
    printf("Failed to set private key\n");
    goto ecc_sig_error;
  }
  if(!EC_POINT_mul(ecgroup, pub, priv, NULL, NULL, bnctx))
  {
    printf("Failed to derive private key\n");
    goto ecc_sig_error;
  }
  if(1 != EC_KEY_set_public_key(eckey, pub))
  {
    printf("Failed to set private key\n");
    goto ecc_sig_error;
  }
  if (NULL == (sig = ECDSA_do_sign(hash, strlen((char*)hash), eckey)))
  {
    printf("Failed to sign\n");
    goto ecc_sig_error;
  }
  if(NULL == (der = malloc(ECDSA_size(eckey) * sizeof(char))))
  {
    printf("Failed to malloc der");
    goto ecc_sig_error;
  }
  unsigned char* der_copy = (unsigned char*)der;
  if(!(der_len = i2d_ECDSA_SIG(sig, &der_copy)))
  {
    printf("Failed to DER encode the signature\n");
    goto ecc_sig_error;
  }
  if(!bytes_to_hex(der, der_len, sig_hex))
  {
    printf("Failed to generate signature string\n");
    goto ecc_sig_error;
  }

ecc_sig_error:
  if((err = ERR_get_error()))
    printf("SSL ERROR: %s\n",ERR_error_string(err, NULL));
  BN_CTX_free(bnctx);
  EC_GROUP_free(ecgroup);
  EC_KEY_free(eckey);
  EC_POINT_free(pub);
  BN_free(priv);
  free(sig);
  free(der);
  return ret;
}

int create_keys(char** pub_hex, char** priv_hex)
{
  EC_KEY   *eckey      = NULL;
  EC_GROUP *ecgroup    = NULL;
  BN_CTX *bnctx        = NULL;
  const EC_POINT *pub;
  const BIGNUM *priv;
  char* pub_str        = NULL;
  char* priv_str       = NULL;
  unsigned long err;

  if (NULL == (eckey = EC_KEY_new()))
  {
    printf("Failed to create new EC Key\n");
    goto ecc_sign_error;
  }
  if (NULL == (ecgroup = EC_GROUP_new_by_curve_name(curve_name)))
  {
    printf("Failed to create new EC Group\n");
    goto ecc_sign_error;
  }
  if (1 != EC_KEY_set_group(eckey,ecgroup))
  {
    printf("Failed to set group for EC Key\n");
    goto ecc_sign_error;
  }
  if(1 != EC_KEY_generate_key(eckey))
  {
    printf("Error creating key\n");
    goto ecc_sign_error;
  }
  if (NULL == (bnctx = BN_CTX_new()))
  {
    printf("Failed to generate bignum context\n");
    goto ecc_sign_error;
  }

  pub = EC_KEY_get0_public_key(eckey);
  priv = EC_KEY_get0_private_key(eckey);

  if (NULL == (pub_str = EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, bnctx)))
  {
    printf("Failed to generate public key string\n");
    goto ecc_sign_error;
  }
  if (NULL == (priv_str = BN_bn2hex(priv)))
  {
    printf("Failed to generate private key string\n");
    goto ecc_sign_error;
  }

  *pub_hex  = pub_str;
  *priv_hex = priv_str;
  BN_CTX_free(bnctx);
  EC_GROUP_free(ecgroup);
  EC_KEY_free(eckey);
  return 1;

ecc_sign_error:
  if((err = ERR_get_error()))
    printf("SSL ERROR: %s\n",ERR_error_string(err, NULL));
  BN_CTX_free(bnctx);
  EC_GROUP_free(ecgroup);
  EC_KEY_free(eckey);
  free(pub_str);
  free(priv_str);
  return 0;
}
