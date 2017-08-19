#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define curve_name NID_secp224r1

typedef struct _myCert_ {
  const char* owner;
  char  pub_key[57*2 + 1];
  char* priv_key;
  char  signature[128 + 1];
} myCert;

int create_keys_hex(char** pub_hex, char** priv_hex);
int create_key(EC_KEY **eckey);
int bytes_to_hex(unsigned char* bytes, int der_len, char** hex_str);
int hex_to_bytes(char* hex, unsigned char** bytes);
int verify_signature(unsigned char* hash, char* signature, char* pub_key);
int sign(unsigned char* hash, const BIGNUM *priv, ECDSA_SIG** signature);
int sign_hex(unsigned char* hash, char* priv_hex, char** sig_hex);
int sig_to_hex(ECDSA_SIG* sig, int key_size, char** sig_hex);
int hash_mycert(myCert* cert, unsigned char** hash);
int sign_mycert_hex(myCert* cert, char* private_key);
int sign_mycert_file(myCert* cert, char* private_key);
int verify_mycert(myCert* cert, char* pub_key);
int create_new_cert(const char* owner, myCert** cert);
void print_mycert(myCert* cert);
int generate_key_file(char* filename, char enc, unsigned char* password);
int get_pubic_key(char* filename, unsigned char* password);

int main(int argc, char* argv[])
{
  //char *sig = NULL, *pub_key = NULL, *priv_key = NULL;
  //int verify_res;
  //myCert cert;
  //myCert *cert_ptr = &cert;
  char* filename = NULL;
  char* owner    = NULL;
  unsigned char* password = NULL;
  char create_pem = 0;
  char create_cert = 0;
  char encrypt = 0;
  char print_pubic_key = 0;
  int c;

  while ((c = getopt (argc, argv, "f:o:p:ecsr")) != -1)
    switch (c)
      {
      case 'o':
        owner = optarg;
        break;
      case 'f':
        filename = optarg;
        break;
      case 'p':
        password = (unsigned char*)optarg;
        break;
      case 'c':
        create_cert = 1;
        break;
      case 's':
        create_pem = 1;
        break;
      case 'r':
        print_pubic_key = 1;
        break;
      case 'e':
        encrypt = 1;
        break;
      case '?':
        if (optopt == 'f' || optopt == 'o' || optopt == 'p')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        return 1;
      default:
        abort ();
      }

  if(create_pem)
  {
    if(!filename)
    {
      printf("filename is missing\n");
      return EXIT_FAILURE;
    }
    generate_key_file(filename, encrypt, password);
  }
  if(create_cert)
  {
    myCert cert;
    myCert *cert_ptr = &cert;
    if(!filename || !owner)
    {
      printf("Filename or owner is missing\n");
      return EXIT_FAILURE;
    }
    create_new_cert(owner, &cert_ptr);
    sign_mycert_file(cert_ptr, filename);
    print_mycert(cert_ptr);
  }
  if(print_pubic_key)
  {
    if(!filename)
    {
      printf("filename is missing\n");
      return EXIT_FAILURE;
    }
    get_pubic_key(filename, password);
  }

  /*
  create_keys(&pub_key, &priv_key);
  printf("Public key : %s\nPrivate key: %s\n", pub_key, priv_key);
  sign_hex((unsigned char*)"this is the second hash", priv_key, &sig);
  printf("Signature: %s\n", sig);
  verify_res = verify_signature((unsigned char*)"this is the second hash", sig, pub_key);
  printf("Verification result: %s\n", verify_res ? "SUCCESS" : "FAIL");
  printf("Signature length  : %d\n", (int)strlen(sig));
  printf("Private key length: %d\n", (int)strlen(priv_key));
  printf("Public key length : %d\n", (int)strlen(pub_key));

  create_new_cert("Alexander Wachter", &cert_ptr);
  sign_mycert_hex(cert_ptr, priv_key);
  print_mycert(cert_ptr);
  verify_res = verify_mycert(cert_ptr, pub_key);
  printf("Certificate verification result: %s\n", verify_res ? "SUCCESS" : "FAIL");
  free(pub_key);
  free(priv_key);
  free(cert.priv_key);*/

  return EXIT_SUCCESS;
}

int generate_key_file(char* filename, char enc, unsigned char* password)
{
  FILE* pem_file;
  EC_KEY *eckey = NULL;
  char* pub_hex = NULL;
  BN_CTX *bnctx = NULL;

  if (NULL == (bnctx = BN_CTX_new()))
  {
    printf("Failed to generate bignum context\n");
    return 0;
  }
  if(!(pem_file = fopen(filename, "w")))
  {
    printf("Failed to create file %s\n", filename);
    return 0;
  }
  create_key(&eckey);
  PEM_write_ECPrivateKey(pem_file, eckey, enc ? EVP_aes_256_cbc() : NULL,
                         password, password ? strlen((char*)password) : 0, NULL, NULL);

  pub_hex = EC_POINT_point2hex(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey),
                               POINT_CONVERSION_UNCOMPRESSED, bnctx);
  printf("Pubkey: %s\n", pub_hex);

  free(pub_hex);
  fclose(pem_file);
  EC_KEY_free(eckey);
  BN_CTX_free(bnctx);
  return 1;
}

int get_pubic_key(char* filename, unsigned char* password)
{
  FILE* pem_file;
  EC_KEY *eckey = NULL;
  const EC_GROUP *ecgroup;
  EC_POINT* pub = NULL;
  const BIGNUM* priv;
  BN_CTX *bnctx = NULL;
  char* pub_hex = NULL;
  unsigned long err;
  int ret = 0;

  OpenSSL_add_all_algorithms();

  if(!(pem_file = fopen(filename, "r")))
  {
    printf("Failed to open file %s\n", filename);
    return 0;
  }
  if (NULL == (eckey = EC_KEY_new()))
  {
    printf("Failed to create new EC Key\n");
    goto ecc_get_pub_error;
  }
  if(NULL == (PEM_read_ECPrivateKey(pem_file, &eckey, NULL, password)))
  {
    printf("Failed to read public key from file %s\n", filename);
    goto ecc_get_pub_error;
  }
  if (NULL == (bnctx = BN_CTX_new()))
  {
    printf("Failed to generate bignum context\n");
    goto ecc_get_pub_error;
  }

  ecgroup = EC_KEY_get0_group(eckey);
  priv = EC_KEY_get0_private_key(eckey);

  if(NULL == (pub = EC_POINT_new(ecgroup)))
  {
    printf("Failed to create public key\n");
    goto ecc_get_pub_error;
  }
  if(!ecgroup || !priv)
  {
    printf("Failed to read group or private key\n");
    goto ecc_get_pub_error;
  }
  if(!EC_POINT_mul(ecgroup, pub, priv, NULL, NULL, bnctx))
  {
    printf("Failed to derive private key\n");
    goto ecc_get_pub_error;
  }

  if(!(pub_hex = EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, bnctx)))
  {
    printf("Failed to convert EC_POINT to hex\n");
  }
  printf("Pubkey: %s\n", pub_hex);
  ret = 1;

ecc_get_pub_error:
  if((err = ERR_get_error()))
    printf("SSL ERROR: %s\n",ERR_error_string(err, NULL));
  fclose(pem_file);
  free(pub_hex);
  EC_POINT_free(pub);
  EC_KEY_free(eckey);
  BN_CTX_free(bnctx);
  return ret;
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
  if(!create_keys_hex(&pub_key, &priv_key))
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

int sign_mycert_hex(myCert* cert, char* sign_priv_key)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned char *hash_ptr = hash;
  char* signature = cert->signature;

  if(!hash_mycert(cert, &hash_ptr))
    return 0;
  if(!sign_hex(hash, sign_priv_key, &signature))
    return 0;
  return 1;
}

int sign_mycert_file(myCert* cert, char* file_name)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned char *hash_ptr = hash;
  int ret = 0, key_size;
  ECDSA_SIG* sig;
  FILE* pem_file;
  char* signature = cert->signature;
  EC_KEY *eckey = NULL;
  EVP_PKEY *pkey = NULL;

  if(!(pem_file = fopen(file_name, "r")))
  {
    printf("Failed to open file %s\n", file_name);
    return ret;
  }
  PEM_read_PrivateKey(pem_file, &pkey, NULL, NULL);
  eckey = EVP_PKEY_get1_EC_KEY(pkey);
  if(!hash_mycert(cert, &hash_ptr))
    return ret;
  if(!(key_size = sign(hash, EC_KEY_get0_private_key(eckey), &sig)))
    return ret;
  ret = sig_to_hex(sig, key_size, &signature);
  
  fclose(pem_file);
  EVP_PKEY_free(pkey);
  free(sig);
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

int sig_to_hex(ECDSA_SIG* sig, int key_size, char** sig_hex)
{
  unsigned char* der = NULL;
  int ret = 0, der_len = 0;

   if(NULL == (der = malloc(key_size * sizeof(char))))
  {
    printf("Failed to malloc der");
    return 0;
  }
  unsigned char* der_copy = (unsigned char*)der;
  if(!(der_len = i2d_ECDSA_SIG(sig, &der_copy)))
  {
    printf("Failed to DER encode the signature\n");
    goto ecc_sig_hex_error;
  }
  if(!bytes_to_hex(der, der_len, sig_hex))
  {
    printf("Failed to generate signature string\n");
    goto ecc_sig_hex_error;
  }
  ret = 1;
ecc_sig_hex_error:
  free(der);
  return ret;
}

int sign_hex(unsigned char* hash, char* priv_hex, char** sig_hex)
{
  BIGNUM *priv       = NULL;
  ECDSA_SIG *sig     = NULL;
  int key_size;
  unsigned long err;
  int ret = 0;

  if (!BN_hex2bn(&priv, priv_hex))
  {
    printf("Failed to read private key hex\n");
    goto ecc_sig_hex_error;
  }
  if(!(key_size = sign(hash, priv, &sig)))
  {
    printf("signation failed\n");
    goto ecc_sig_hex_error;
  }
  ret = sig_to_hex(sig, key_size, sig_hex);

ecc_sig_hex_error:
  if((err = ERR_get_error()))
    printf("SSL ERROR: %s\n",ERR_error_string(err, NULL));
  BN_free(priv);
  free(sig);
  return ret;
}

int sign(unsigned char* hash, const BIGNUM *priv, ECDSA_SIG** signature)
{
  EC_KEY   *eckey    = NULL;
  EC_GROUP *ecgroup  = NULL;
  EC_POINT* pub      = NULL;
  BN_CTX *bnctx      = NULL;
  ECDSA_SIG *sig     = NULL;
  unsigned long err;
  int ret = 0, key_size;

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
  key_size = ECDSA_size(eckey);
  if (NULL == (sig = ECDSA_do_sign(hash, strlen((char*)hash), eckey)))
  {
    printf("Failed to sign\n");
    goto ecc_sig_error;
  }
  *signature = sig;
  BN_CTX_free(bnctx);
  EC_GROUP_free(ecgroup);
  EC_KEY_free(eckey);
  EC_POINT_free(pub);
  return key_size;

ecc_sig_error:
  if((err = ERR_get_error()))
    printf("SSL ERROR: %s\n",ERR_error_string(err, NULL));
  BN_CTX_free(bnctx);
  EC_GROUP_free(ecgroup);
  EC_KEY_free(eckey);
  EC_POINT_free(pub);
  free(sig);
  return ret;
}

int create_key(EC_KEY **eckey)
{
  EC_KEY* new_key;
  EC_GROUP *ecgroup    = NULL;
  unsigned long err;

  new_key = *eckey;
  if(NULL == new_key)
  {
    if (NULL == (new_key = EC_KEY_new()))
    {
      printf("Failed to create new EC Key\n");
      goto ecc_sign_error;
    }
    *eckey = new_key;
  }

  if (NULL == (ecgroup = EC_GROUP_new_by_curve_name(curve_name)))
  {
    printf("Failed to create new EC Group\n");
    goto ecc_sign_error;
  }
  if (1 != EC_KEY_set_group(new_key,ecgroup))
  {
    printf("Failed to set group for EC Key\n");
    goto ecc_sign_error;
  }
  if(1 != EC_KEY_generate_key(new_key))
  {
    printf("Error creating key\n");
    goto ecc_sign_error;
  }

  EC_GROUP_free(ecgroup);
  return 1;

ecc_sign_error:
  if((err = ERR_get_error()))
    printf("SSL ERROR: %s\n",ERR_error_string(err, NULL));
  EC_GROUP_free(ecgroup);
  EC_KEY_free(new_key);
  return 0;
}

int create_keys_hex(char** pub_hex, char** priv_hex)
{
  EC_KEY   *eckey      = NULL;
  EC_GROUP *ecgroup    = NULL;
  BN_CTX *bnctx        = NULL;
  const EC_POINT *pub;
  const BIGNUM *priv;
  char* pub_str        = NULL;
  char* priv_str       = NULL;
  unsigned long err;

  if(1 != create_key(&eckey))
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
