#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>


#define curve_name NID_secp224r1
int create_signature(unsigned char* hash, char** pub_hex, char** priv_hex, char** sig_hex);
char* der_to_hex(unsigned char* der, int der_len);
int hex_to_der(char* hex_der, unsigned char** der);
int verify_signature(unsigned char* hash, char* signature, char* pub_key);

int main(int argc, char* argv[])
{
  char *sig, *pub_key, *priv_key;
  //unsigned char *der;
  //int der_len;
  int verify_res;

  create_signature((unsigned char*)"this is the hash", &pub_key, &priv_key, &sig);
  printf("Public key : %s\nPrivate key: %s\nSignature  : %s\n", pub_key, priv_key, sig);
  //der_len = hex_to_der(sig, &der);
  //printf("Signature  : %s\nLength: %d\n", der_to_hex(der, der_len), der_len);

  verify_res = verify_signature((unsigned char*)"this is the hash", sig, pub_key);
  printf("Verification result: %s\n", verify_res ? "SUCCESS" : "FAIL");

  return EXIT_SUCCESS;
}

int hex_to_der(char* hex_der, unsigned char** der)
{
  int len, i;
  char *hex_der_ptr, val, digit_val;
  unsigned char *der_ptr;

  if(!hex_der)
    return 0;
  len = strlen(hex_der);
  der_ptr = malloc(len * sizeof(char) / 2);
  *der = der_ptr;
  if(!der_ptr)
    return 0;
  hex_der_ptr = hex_der;
  for(i = 0; i < len / 2; i++)
  {
    digit_val = *(hex_der_ptr++);
    if( !((digit_val >= '0' && digit_val <= '9') || (digit_val >= 'A' && digit_val <= 'F')))
    {
      free(der_ptr);
      return 0;
    }
    digit_val = digit_val > '9' ? digit_val - 'A' + 10 : digit_val - '0';
    val = digit_val * 16;
    digit_val = *(hex_der_ptr++);
    if( !((digit_val >= '0' && digit_val <= '9') || (digit_val >= 'A' && digit_val <= 'F')))
    {
      free(der_ptr);
      return 0;
    }
    digit_val = digit_val > '9' ? digit_val - 'A' + 10 : digit_val - '0';
    val += digit_val;
    der_ptr[i] = val;
  }
  return len/2;
}

char* der_to_hex(unsigned char* der, int der_len)
{
  int i;
  char *str_ptr, *ret_str, val, val_digit;
  int str_size = der_len * sizeof(char) * 2;

  ret_str = malloc(str_size + 1);
  if(!ret_str)
    return NULL;

  str_ptr = ret_str;
  for(i = 0; i < der_len; i++)
  {
    val = der[i];
    val_digit = (val & 0xF0) >> 4;
    *(str_ptr++) = val_digit < 10 ? val_digit + '0' : val_digit - 10 + 'A';
    val_digit = val & 0x0F;
    *(str_ptr++) = val_digit < 10 ? val_digit + '0' : val_digit - 10 + 'A';
  }
  *str_ptr = '\0';
  return ret_str;
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
  if(! (der_len = hex_to_der(signature, &der)))
  {
    printf("Failed to create der from signature\n");
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

int create_signature(unsigned char* hash, char** pub_hex, char** priv_hex, char** sig_hex)
{
  EC_KEY   *eckey      = NULL;
  EC_GROUP *ecgroup    = NULL;
  ECDSA_SIG *signature = NULL;
  BN_CTX *bnctx        = NULL;
  const EC_POINT *pub;
  const BIGNUM *priv;
  char* pub_str        = NULL;
  char* priv_str       = NULL;
  unsigned char* der            = NULL;
  char* der_str        = NULL;
  int der_len;
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
  signature = ECDSA_do_sign(hash, strlen((char*)hash), eckey);
  if (NULL == signature)
  {
    printf("Failed to generate EC Signature\n");
    goto ecc_sign_error;
  }
  der = malloc(ECDSA_size(eckey) * sizeof(char));
  unsigned char* der_copy = (unsigned char*)der;
  if(!(der_len = i2d_ECDSA_SIG(signature, &der_copy)))
  {
    printf("Failed to DER encode the signature\n");
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
  if(!(der_str = der_to_hex(der, der_len)))
  {
    printf("Failed to generate signature string\n");
    goto ecc_sign_error;
  }
  int verify_status = ECDSA_do_verify(hash, strlen((char*)hash), signature, eckey);

  if (verify_status != 1)
  {
    printf("Signature verification failed");
    goto ecc_sign_error;
  }

  *pub_hex  = pub_str;
  *priv_hex = priv_str;
  *sig_hex  = der_str;
  BN_CTX_free(bnctx);
  EC_GROUP_free(ecgroup);
  EC_KEY_free(eckey);
  free(der);
  return EXIT_SUCCESS;

ecc_sign_error:
  if((err = ERR_get_error()))
    printf("SSL ERROR: %s\n",ERR_error_string(err, NULL));
  BN_CTX_free(bnctx);
  EC_GROUP_free(ecgroup);
  EC_KEY_free(eckey);
  free(pub_str);
  free(priv_str);
  free(der);
  return EXIT_FAILURE;
}
