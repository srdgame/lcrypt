#include "lcrypt.h"
#include <errno.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L || defined(OPENSSL_NO_SM2) || defined(OPENSSL_NO_SM3) || defined(OPENSSL_NO_SM4)

/* 不支持的情况下使用需要抛出异常. */
#define SM_THROW(L) luaL_error(L, "The current environment does not support the SM2/SM3/SM4 algorithm.")

int lsm3(lua_State *L) { return SM_THROW(L); }
int lhmac_sm3(lua_State *L) { return SM_THROW(L); }

int lsm4_cbc_encrypt(lua_State *L) { return SM_THROW(L); }
int lsm4_cbc_decrypt(lua_State *L) { return SM_THROW(L); }

int lsm4_ecb_encrypt(lua_State *L) { return SM_THROW(L); }
int lsm4_ecb_decrypt(lua_State *L) { return SM_THROW(L); }

int lsm4_ofb_encrypt(lua_State *L) { return SM_THROW(L); }
int lsm4_ofb_decrypt(lua_State *L) { return SM_THROW(L); }

int lsm4_ctr_encrypt(lua_State *L) { return SM_THROW(L); }
int lsm4_ctr_decrypt(lua_State *L) { return SM_THROW(L); }

int lsm2keygen(lua_State *L){ return SM_THROW(L); }

int lsm2sign(lua_State *L) { return SM_THROW(L); }
int lsm2verify(lua_State *L) { return SM_THROW(L); }

int lsm2key_write(lua_State *L) { return SM_THROW(L); }

#else

#ifndef SM3_BLOCK_SIZE
	#define SM3_BLOCK_SIZE (32)
#endif

int lsm3(lua_State *L) {
	size_t textsize = 0;
	const uint8_t * text = (const uint8_t *)luaL_checklstring(L, 1, &textsize);
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md_ctx, EVP_sm3(), NULL);
	EVP_DigestUpdate(md_ctx, text, textsize);
	uint32_t result_size = SM3_BLOCK_SIZE;
	uint8_t result[result_size];
	EVP_DigestFinal_ex(md_ctx, result, &result_size);
	EVP_MD_CTX_free(md_ctx);
	lua_pushlstring(L, (const char *)result, SM3_BLOCK_SIZE);
	return 1;
}

int lhmac_sm3(lua_State *L) {
  size_t key_sz = 0;
  size_t text_sz = 0;
  const char * key = luaL_checklstring(L, 1, &key_sz);
  if (!key || key_sz <= 0)
    return luaL_error(L, "Invalid key value.");

  const char * text = luaL_checklstring(L, 2, &text_sz);
  if (!text || text_sz <= 0)
    return luaL_error(L, "Invalid text value.");

  uint32_t result_len = SM3_BLOCK_SIZE;
  uint8_t result[result_len];
  memset(result, 0x0, result_len);
  HMAC(EVP_sm3(), (const unsigned char*)key, key_sz, (const unsigned char*)text, text_sz, result, &result_len);
  lua_pushlstring(L, (const char *)result, result_len);
  return 1;
}

/* 加密函数 */ 
static inline int sm4_encrypt(lua_State *L, const EVP_CIPHER *evp_md, const uint8_t *iv, const uint8_t *key, const uint8_t *text, size_t tsize) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return luaL_error(L, "allocate EVP failed.");

  if (1 != EVP_EncryptInit_ex(ctx, evp_md, NULL, key, iv)){
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return luaL_error(L, "SM4_ENCRYPT_INIT failed.");
  }

  EVP_CIPHER_CTX_set_padding(ctx, 1);
  // printf("key_len = %d\n", EVP_CIPHER_CTX_key_length(ctx));
  // printf("iv_len = %d\n", EVP_CIPHER_CTX_iv_length(ctx));
  // printf("block_size = %d\n", EVP_CIPHER_CTX_block_size(ctx));

  int out_size = tsize + EVP_MAX_BLOCK_LENGTH;
  uint8_t *out = lua_newuserdata(L, out_size);


  int update_len = out_size;
  if (1 != EVP_EncryptUpdate(ctx, out, &update_len, text, tsize)){
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return luaL_error(L, "SM4_ENCRYPT_UPDATE failed.");
  }

  int final_len = out_size;
  if (1 != EVP_EncryptFinal(ctx, out + update_len, &final_len)){
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return luaL_error(L, "SM4_ENCRYPT_FINAL failed.");
  }

  lua_pushlstring(L, (const char*)out, update_len + final_len);
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);
  return 1;
}

/* 解密函数 */ 
static inline int sm4_decrypt(lua_State *L, const EVP_CIPHER *evp_md, const uint8_t *iv, const uint8_t *key, const uint8_t *cipher, size_t csize) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return luaL_error(L, "allocate EVP failed.");

  if (1 != EVP_DecryptInit_ex(ctx, evp_md, NULL, key, iv)){
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return luaL_error(L, "SM4_DECRYPT_INIT failed.");
  }

  EVP_CIPHER_CTX_set_padding(ctx, 1);
  // printf("key_len = %d\n", EVP_CIPHER_CTX_key_length(ctx));
  // printf("iv_len = %d\n", EVP_CIPHER_CTX_iv_length(ctx));
  // printf("block_size = %d\n", EVP_CIPHER_CTX_block_size(ctx));

  int out_size = csize + EVP_MAX_BLOCK_LENGTH;
  uint8_t *out = lua_newuserdata(L, out_size);

  int update_len = out_size;
  if (1 != EVP_DecryptUpdate(ctx, out, &update_len, cipher, csize)){
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return luaL_error(L, "SM4_DECRYPT_UPDATE failed.");
  }

  int final_len = out_size;
  if (1 != EVP_DecryptFinal_ex(ctx, out + update_len, &final_len)){
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return luaL_error(L, "SM4_DECRYPT_FINAL failed.");
  }

  lua_pushlstring(L, (const char*)out, update_len + final_len);
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);
  return 1;
}

static inline const EVP_CIPHER* get_cipher(lua_State *L, int mode) {
  switch(mode){
    case 1:
      return EVP_sm4_cbc();
    case 2:
      return EVP_sm4_ecb();
    case 3:
      return EVP_sm4_ofb();
    case 4:
      return EVP_sm4_ctr();
  }
  return luaL_error(L, "Invalid SM4 CIPHER."), NULL;
}

static inline int lua_getarg(lua_State *L, const char **iv, const char **key, const char **text, size_t *tsize) {
  *key = luaL_checkstring(L, 1);
  if (!key)
    return luaL_error(L, "Invalid key");

  size_t size = 0;
  *text = luaL_checklstring(L, 2, &size);
  if (!text)
    return luaL_error(L, "Invalid text");
  *tsize = size;

  *iv = luaL_checkstring(L, 3);
  if (!iv)
    return luaL_error(L, "Invalid iv");
  return 1;
}


/* SM4加密函数的分组类型封装 */
int lsm4_cbc_encrypt(lua_State *L) {
  const char *iv; const char *key; const char *text; size_t tsize;
 //  lua_getarg(L, &iv, &key, &text, &tsize);
	// return 1;
  return lua_getarg(L, &iv, &key, &text, &tsize) && sm4_encrypt(L, get_cipher(L, 1), (const uint8_t *)iv, (const uint8_t *)key, (const uint8_t *)text, tsize);
}

int lsm4_ecb_encrypt(lua_State *L) {
  const char *iv; const char *key; const char *text; size_t tsize;
  // lua_getarg(L, &iv, &key, &text, &tsize);
  // return 1;
  return lua_getarg(L, &iv, &key, &text, &tsize) && sm4_encrypt(L, get_cipher(L, 2), (const uint8_t *)iv, (const uint8_t *)key, (const uint8_t *)text, tsize);
}

int lsm4_ofb_encrypt(lua_State *L) {
  const char *iv; const char *key; const char *text; size_t tsize;
 //  lua_getarg(L, &iv, &key, &text, &tsize);
	// return 1;
  return lua_getarg(L, &iv, &key, &text, &tsize) && sm4_encrypt(L, get_cipher(L, 3), (const uint8_t *)iv, (const uint8_t *)key, (const uint8_t *)text, tsize);
}

int lsm4_ctr_encrypt(lua_State *L) {
  const char *iv; const char *key; const char *text; size_t tsize;
  // lua_getarg(L, &iv, &key, &text, &tsize);
  // return 1;
  return lua_getarg(L, &iv, &key, &text, &tsize) && sm4_encrypt(L, get_cipher(L, 4), (const uint8_t *)iv, (const uint8_t *)key, (const uint8_t *)text, tsize);
}


/* SM4解密函数的分组类型封装 */
int lsm4_cbc_decrypt(lua_State *L) {
  const char *iv; const char *key; const char *cipher; size_t csize;
  // lua_getarg(L, &iv, &key, &cipher, &csize);
  // return 1;
  return lua_getarg(L, &iv, &key, &cipher, &csize) && sm4_decrypt(L, get_cipher(L, 1), (const uint8_t *)iv, (const uint8_t *)key, (const uint8_t *)cipher, csize);
}

int lsm4_ecb_decrypt(lua_State *L) {
  const char *iv; const char *key; const char *cipher; size_t csize;
  // lua_getarg(L, &iv, &key, &cipher, &csize);
  // return 1;
  return lua_getarg(L, &iv, &key, &cipher, &csize) && sm4_decrypt(L, get_cipher(L, 2), (const uint8_t *)iv, (const uint8_t *)key, (const uint8_t *)cipher, csize);
}

int lsm4_ofb_decrypt(lua_State *L) {
  const char *iv; const char *key; const char *cipher; size_t csize;
  // lua_getarg(L, &iv, &key, &cipher, &csize);
  // return 1;
  return lua_getarg(L, &iv, &key, &cipher, &csize) && sm4_decrypt(L, get_cipher(L, 3), (const uint8_t *)iv, (const uint8_t *)key, (const uint8_t *)cipher, csize);
}

int lsm4_ctr_decrypt(lua_State *L) {
  const char *iv; const char *key; const char *cipher; size_t csize;
  // lua_getarg(L, &iv, &key, &cipher, &csize);
  // return 1;
  return lua_getarg(L, &iv, &key, &cipher, &csize) && sm4_decrypt(L, get_cipher(L, 4), (const uint8_t *)iv, (const uint8_t *)key, (const uint8_t *)cipher, csize);
}

// 读取私钥
static inline EVP_PKEY* load_sm2prikey(lua_State *L) {
  const char* private_keyname = luaL_checkstring(L, 1);
  FILE *fp = fopen(private_keyname, "rb");
  if (!fp)
    return luaL_error(L, "Can't find `SM`2 privatekey in [%s] file.", private_keyname), NULL;

  EVP_PKEY *sm2key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  if (!sm2key) {
    fclose(fp);
    return luaL_error(L, "Invalid `SM2` private key in [%s] file.", private_keyname), NULL;
  }
  fclose(fp);
  return sm2key;
}

// 读取公钥
static inline EVP_PKEY* load_sm2pubkey(lua_State *L) {
  const char* public_keyname = luaL_checkstring(L, 1);
  FILE *fp = fopen(public_keyname, "rb");
  if (!fp)
    return luaL_error(L, "Can't find `SM`2 publickey in [%s] file.", public_keyname), NULL;

  EVP_PKEY *sm2key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
  if (!sm2key) {
    fclose(fp);
    return luaL_error(L, "Invalid `SM2` publickey key in [%s] file.", public_keyname), NULL;
  }
  fclose(fp);
  return sm2key;
}

/* 生成 SM2 `私钥`与`公钥` */ 
static inline int sm2keygen(lua_State *L) {
  const char* private_keyname = luaL_checkstring(L, 1);
  const char* public_keyname = luaL_checkstring(L, 2);

	EVP_PKEY *sm2key = EVP_PKEY_new();
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	EVP_PKEY_keygen_init(pctx);

	if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2) || !EVP_PKEY_CTX_set_ec_param_enc(pctx, OPENSSL_EC_NAMED_CURVE) || EVP_PKEY_keygen(pctx, &sm2key) <= 0 ){
	  EVP_PKEY_free(sm2key);
	  EVP_PKEY_CTX_free(pctx);
		return luaL_error(L, "Generate SM2 key error.");
	}

  FILE *private_fp = fopen(private_keyname, "wb");
  FILE *public_fp = fopen(public_keyname, "wb");
  if (!private_fp || !public_fp) {
    if (private_fp)
      fclose(private_fp);
    if (public_fp)
      fclose(public_fp);
    EVP_PKEY_free(sm2key);
    EVP_PKEY_CTX_free(pctx);
    return luaL_error(L, "Write file failed after generate SM2 key.");
  }

  if (1 != PEM_write_PrivateKey(private_fp, sm2key, NULL, NULL, 0, NULL, NULL) || 1 != PEM_write_PUBKEY(public_fp, sm2key)) {
    fclose(private_fp);
    fclose(public_fp);
    EVP_PKEY_free(sm2key);
    EVP_PKEY_CTX_free(pctx);
    return luaL_error(L, "`SM2` privatekey/publickey write file failed.");
  }

  fclose(private_fp);
  fclose(public_fp);
  // 回收内存
  EVP_PKEY_free(sm2key);
  EVP_PKEY_CTX_free(pctx);
  return 0;
}

int lsm2keygen(lua_State *L){
	return sm2keygen(L);
}

int lsm2sign(lua_State *L){
	size_t idsize = 0;
	const char* id = luaL_checklstring(L, 2, &idsize);

	size_t tsize = 0;
	const char* text = luaL_checklstring(L, 3, &tsize);

	EVP_PKEY *sm2key = load_sm2prikey(L);
	EVP_PKEY_set_alias_type(sm2key, EVP_PKEY_SM2);

	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(sm2key, NULL);
	EVP_PKEY_CTX_set1_id(pctx, id, idsize);
	EVP_MD_CTX_set_pkey_ctx(md_ctx, pctx);
	EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, sm2key);

	size_t osize = 0;
	if (1 != EVP_DigestSign(md_ctx, NULL, &osize, (uint8_t*)text, tsize)) {
		EVP_PKEY_free(sm2key);
		EVP_PKEY_CTX_free(pctx);
		EVP_MD_CTX_free(md_ctx);
		return luaL_error(L, "EVP_DigestSign failed.");
	}

	const char *out = lua_newuserdata(L, osize);
	if (!out) {
		EVP_PKEY_free(sm2key);
		EVP_PKEY_CTX_free(pctx);
		EVP_MD_CTX_free(md_ctx);
		return luaL_error(L, "Allocated out buffer failed.");
	}

	if (1 != EVP_DigestSign(md_ctx, (uint8_t*)out, &osize, (uint8_t*)text, tsize) ){
		EVP_PKEY_free(sm2key);
		EVP_PKEY_CTX_free(pctx);
		EVP_MD_CTX_free(md_ctx);
		return luaL_error(L, "EVP_DigestSign failed.");
	}

	lua_pushlstring(L, out, osize);

	EVP_PKEY_free(sm2key);
	EVP_PKEY_CTX_free(pctx);
	EVP_MD_CTX_free(md_ctx);
	return 1;
}

int lsm2verify(lua_State *L){
  size_t idsize = 0;
  const char* id = luaL_checklstring(L, 2, &idsize);

  size_t tsize = 0;
  const char* text = luaL_checklstring(L, 3, &tsize);

  size_t csize = 0;
  const char* cipher = luaL_checklstring(L, 4, &csize);

  EVP_PKEY *sm2key = load_sm2pubkey(L);
  EVP_PKEY_set_alias_type(sm2key, EVP_PKEY_SM2);

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(sm2key, NULL);
  EVP_PKEY_CTX_set1_id(pctx, id, idsize);
  EVP_MD_CTX_set_pkey_ctx(md_ctx, pctx);
  EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, sm2key);

  if (1 == EVP_DigestVerify(md_ctx, (uint8_t*)cipher, csize, (uint8_t*)text, tsize))
    lua_pushboolean(L, 1);
  else
    lua_pushboolean(L, 0);

  EVP_PKEY_free(sm2key);
  EVP_PKEY_CTX_free(pctx);
  EVP_MD_CTX_free(md_ctx);
  return 1;
}

int lsm2encrypt(lua_State *L){
  size_t tsize = 0;
  const char* text = luaL_checklstring(L, 2, &tsize);

  EVP_PKEY *sm2key = load_sm2pubkey(L);
  EVP_PKEY_set_alias_type(sm2key, EVP_PKEY_SM2);

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(sm2key, NULL);

  if (!pctx) {
	EVP_PKEY_free(sm2key);
    return luaL_error(L, "EVP_PKEY_CTX_new failed.");
  }

  if (1 != EVP_PKEY_encrypt_init(pctx)) {
	EVP_PKEY_free(sm2key);
	EVP_PKEY_CTX_free(pctx);
    return luaL_error(L, "EVP_PKEY_encrypt_init failed.");
  }

  size_t out_size = 0;
  if (1 != EVP_PKEY_encrypt(pctx, NULL, &out_size, (const unsigned char*)text, tsize)) {
	EVP_PKEY_free(sm2key);
	EVP_PKEY_CTX_free(pctx);
    return luaL_error(L, "EVP_PKEY_encrypt failed.");
  }

  uint8_t *out = lua_newuserdata(L, out_size);

  if (1 != EVP_PKEY_encrypt(pctx, out, &out_size, (const unsigned char*)text, tsize)) {
	EVP_PKEY_free(sm2key);
	EVP_PKEY_CTX_free(pctx);
    return luaL_error(L, "EVP_PKEY_encrypt failed.");
  }

  lua_pushlstring(L, (const char*)out, out_size);
  EVP_PKEY_free(sm2key);
  EVP_PKEY_CTX_free(pctx);
  return 1;
}

int lsm2decrypt(lua_State *L){
  size_t tsize = 0;
  const char* text = luaL_checklstring(L, 2, &tsize);

  EVP_PKEY *sm2key = load_sm2prikey(L);
  EVP_PKEY_set_alias_type(sm2key, EVP_PKEY_SM2);

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(sm2key, NULL);

  if (!pctx) {
	EVP_PKEY_free(sm2key);
    return luaL_error(L, "EVP_PKEY_CTX_new failed.");
  }

  if (1 != EVP_PKEY_decrypt_init(pctx)) {
	EVP_PKEY_free(sm2key);
	EVP_PKEY_CTX_free(pctx);
    return luaL_error(L, "EVP_PKEY_decrypt_init failed.");
  }

  size_t out_size = 0;
  if (1 != EVP_PKEY_decrypt(pctx, NULL, &out_size, (const unsigned char*)text, tsize)) {
	EVP_PKEY_free(sm2key);
	EVP_PKEY_CTX_free(pctx);
    return luaL_error(L, "EVP_PKEY_decrypt get size failed.");
  }

  uint8_t *out = lua_newuserdata(L, out_size);

  if (1 != EVP_PKEY_decrypt(pctx, out, &out_size, (const unsigned char*)text, tsize)) {
	EVP_PKEY_free(sm2key);
	EVP_PKEY_CTX_free(pctx);
    return luaL_error(L, "EVP_PKEY_decrypt do decrypt failed.");
  }

  lua_pushlstring(L, (const char*)out, out_size);
  EVP_PKEY_free(sm2key);
  EVP_PKEY_CTX_free(pctx);
  return 1;
}

/*
int lsm2key_export(lua_State *L){
	const char* pkey = luaL_checkstring(L, 1);
	const char* keyx = luaL_checkstring(L, 2);
	const char* keyy = luaL_checkstring(L, 3);
	const char* private_keyname = luaL_checkstring(L, 4);
	const char* public_keyname = luaL_checkstring(L, 5);

	EVP_PKEY *sm2key = NULL;
	EC_KEY *ec_key = NULL;
	EC_GROUP *ec_group = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *kp = NULL;
	BIGNUM *kx = NULL;
	BIGNUM *ky = NULL;
	//BIO *outbio = NULL;

	printf("%s: pri_key: %s len: %lu\n", __func__, pkey, strlen(pkey));
	printf("%s: keyx: %s len: %lu\n", __func__, keyx, strlen(keyx));
	printf("%s: keyy: %s len: %lu\n", __func__, keyy, strlen(keyy));

	FILE *private_fp = fopen(private_keyname, "wb");
	FILE *public_fp = fopen(public_keyname, "wb");
	if (!private_fp || !public_fp) {
		return luaL_error(L, "Write file failed after generate SM2 key.");
	}

	if (NULL == (ec_group = EC_GROUP_new_by_curve_name(NID_sm2)))
	{
		printf("%s: EC_GROUP_new_by_curve_name failed\n", __func__);
		goto clean_up;
	} 

	if (NULL == (ec_key = EC_KEY_new())) {
		printf("%s:EC_KEY_new failed\n", __func__);
		goto clean_up;
	}

	if ( (EC_KEY_set_group(ec_key, ec_group) != 1 )){
		printf("%s:EC_KEY_set_group failed\n", __func__);
		goto clean_up;
	}
	if (NULL == (sm2key = EVP_PKEY_new())) {
		printf("%s:EVP_PKEY_new failed\n", __func__);
		goto clean_up;
	}

	if (BN_hex2bn(&kp, pkey)) {
		pt = EC_POINT_new(ec_group);
		if (pt) {
			if (BN_hex2bn(&kx, keyx) &&
					BN_hex2bn(&ky, keyy)) {
				if ( !EC_POINT_set_affine_coordinates(ec_group, pt, kx, ky, NULL)) {
					printf("%s: EC_POINT_set_affine_coordinates failed\n", __func__);
					goto clean_up;
				}
				if ( !EC_KEY_set_public_key(ec_key, pt)) {
					printf("%s: EC_KEY_set_public_key failed\n", __func__);
					goto clean_up;
				}
				if ( !EC_KEY_set_private_key(ec_key, kp)) {
					printf("%s: EC_KEY_set_private_key failed\n", __func__);
					goto clean_up;
				}
				if ( !EVP_PKEY_assign_EC_KEY(sm2key, ec_key)) {
					printf("%s: EVP_PKEY_assign_EC_KEY failed\n", __func__);
					goto clean_up;
				}
				//outbio  = BIO_new(BIO_s_file());
				//outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
				//if(!PEM_write_bio_PrivateKey(outbio, sm2key, NULL, NULL, 0, 0, NULL)) {
				if(!PEM_write_PrivateKey(private_fp, sm2key, NULL, NULL, 0, 0, NULL)) {
					//BIO_printf(outbio, "%s: Error writing private key data in PEM format %d\n", __func__, errno);
					printf("%s: Error writing public key data in PEM format\n", __func__);
					goto clean_up;
				}

				//if(!PEM_write_bio_PUBKEY(outbio, sm2key))
				if(!PEM_write_PUBKEY(public_fp, sm2key)) {
					//BIO_printf(outbio, "%s: Error writing public key data in PEM format\n", __func__);
					printf("%s: Error writing private key data in PEM format\n", __func__);
					goto clean_up;
				}
				
			} else {
				printf("%s: keyx keyy to bn failed\n", __func__);
				goto clean_up;
			}
		} else {
			printf("%s: EC_POINT_new failed\n", __func__);
			goto clean_up;
		}
	} else {
		printf("%s: pkey to bn failed\n", __func__);
		goto clean_up;
	}
clean_up:
	if (private_fp)
		fclose(private_fp);
	if (public_fp)
		fclose(public_fp);
	if (pt)
		EC_POINT_free(pt);
	if (kp)
		BN_free(kp);
	if (kx)
		BN_free(kx);
	if (ky)
		BN_free(ky);
	if (ec_key)
		EC_KEY_free(ec_key);
	if (ec_group)
		EC_GROUP_free(ec_group);
	if (sm2key)
		EVP_PKEY_free(sm2key);
	return 0;
}
*/

// 从公钥和私钥生成证书
int lsm2key_write(lua_State *L) {
	const char* err = NULL;
	const char* pub_key = luaL_checkstring(L, 1);
	const char* public_keyname = luaL_checkstring(L, 2);
	const char* pri_key = luaL_optstring(L, 3, NULL);
	const char* private_keyname = luaL_optstring(L, 4, NULL);

	EVP_PKEY *sm2key = NULL;
	EC_KEY *ec_key = NULL;
	EC_GROUP *ec_group = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *kp = NULL;
	BIGNUM *kx = NULL;
	BIGNUM *ky = NULL;
	char keyx[65] = {0};
	char keyy[65] = {0};
	//BIO *outbio = NULL;
	FILE *public_fp = NULL;
	FILE *private_fp = NULL;

	if (128 != strlen(pub_key)) {
		err = "Private key length error";
		goto clean_up;
	} else {
		memcpy(keyx, pub_key, 64);
		memcpy(keyy, pub_key + 64, 64);
		//printf("%s: keyx: %s len: %lu\n", __func__, keyx, strlen(keyx));
		//printf("%s: keyy: %s len: %lu\n", __func__, keyy, strlen(keyy));
		if (!(BN_hex2bn(&kx, keyx) && BN_hex2bn(&ky, keyy))) {
			err = "Public key string to bn failed";
			goto clean_up;
		}

		public_fp = fopen(public_keyname, "wb");
		if (!public_fp) {
			err = "Failed to open public key file.";
			goto clean_up;
		}
	}
	if (pri_key) {
		if (64 != strlen(pri_key)) {
			err = "Public key length error";
			goto clean_up;
		}
		//printf("%s: pri_key: %s len: %lu\n", __func__, pri_key, strlen(pri_key));
		if (private_keyname == NULL) {
			err = "Private key file path missing";
			goto clean_up;
		}
		if (!BN_hex2bn(&kp, pri_key)) {
			err = "Private key string to bn failed";
			goto clean_up;
		}

		private_fp = fopen(private_keyname, "wb");
		if (!private_fp ) {
			err = "Failed to open private key file.";
			goto clean_up;
		}
	}


	if (NULL == (ec_group = EC_GROUP_new_by_curve_name(NID_sm2)))
	{
		err = "EC_GROUP_new_by_curve_name failed";
		goto clean_up;
	} 

	if (NULL == (ec_key = EC_KEY_new())) {
		err = "EC_KEY_new failed";
		goto clean_up;
	}

	if ( (EC_KEY_set_group(ec_key, ec_group) != 1 )){
		err = "EC_KEY_set_group failed";
		goto clean_up;
	}

	pt = EC_POINT_new(ec_group);
	if (!pt) {
		err = "EC_POINT_new failed";
		goto clean_up;
	}

	if (!EC_POINT_set_affine_coordinates(ec_group, pt, kx, ky, NULL)) {
		err = "EC_POINT_set_affine_coordinates failed";
		goto clean_up;
	}

	if (!EC_KEY_set_public_key(ec_key, pt)) {
		err ="EC_KEY_set_public_key failed";
		goto clean_up;
	}

	if (pri_key && !EC_KEY_set_private_key(ec_key, kp)) {
		err = "EC_KEY_set_private_key failed";
		goto clean_up;
	}

	if (NULL == (sm2key = EVP_PKEY_new())) {
		err = "EVP_PKEY_new failed";
		goto clean_up;
	}

	if ( !EVP_PKEY_assign_EC_KEY(sm2key, ec_key)) {
		err = "EVP_PKEY_assign_EC_KEY failed";
		goto clean_up;
	}

	/*
	outbio  = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
	if(!PEM_write_bio_PrivateKey(outbio, sm2key, NULL, NULL, 0, 0, NULL)) {
	BIO_printf(outbio, "%s: Error writing private key data in PEM format\n", __func__);
	}

	if(!PEM_write_bio_PUBKEY(outbio, sm2key))
	BIO_printf(outbio, "%s: Error writing public key data in PEM format\n", __func__);
	*/	

	if(!PEM_write_PUBKEY(public_fp, sm2key)) {
		err = "Error writing public key data in PEM format";
		goto clean_up;
	}

	if(pri_key && !PEM_write_PrivateKey(private_fp, sm2key, NULL, NULL, 0, 0, NULL)) {
		err = "Error writing private key data in PEM format";
		goto clean_up;
	}

clean_up:
	if (private_fp)
		fclose(private_fp);
	if (public_fp)
		fclose(public_fp);
	if (pt)
		EC_POINT_free(pt);
	if (kp)
		BN_free(kp);
	if (kx)
		BN_free(kx);
	if (ky)
		BN_free(ky);
	// EC_KEY only be free when not assigned to EVP_PKEY
	if (ec_key && !sm2key)
		EC_KEY_free(ec_key);
	if (ec_group)
		EC_GROUP_free(ec_group);
	if (sm2key)
		EVP_PKEY_free(sm2key);

	if (err) {
		return luaL_error(L, err);
	}

	lua_pushboolean(L, 1);
	return 1;
}

/*
// 从公钥生成证书
int lsm2pubkey_write(lua_State *L) {
	const char* err = NULL;
	const char* pub_key = luaL_checkstring(L, 1);
	const char* keyname = luaL_checkstring(L, 2);
	EVP_PKEY *sm2key = NULL;
	EC_KEY *ec_key = NULL;
	EC_GROUP *ec_group = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *kx = NULL;
	BIGNUM *ky = NULL;
	char keyx[65] = {0};
	char keyy[65] = {0};
	//BIO *outbio = NULL;

	FILE *fp = fopen(keyname, "wb");
	if (!fp) {
		err = "Write file failed after generate SM2 key.";
		goto clean_up;
	}

	if (128 != strlen(pub_key)) {
		err = "Private key length error";
		goto clean_up;
	}

	memcpy(keyx, pub_key, 64);
	memcpy(keyy, pub_key + 64, 64);

	printf("%s: keyx: %s len: %lu\n", __func__, keyx, strlen(keyx));
	printf("%s: keyy: %s len: %lu\n", __func__, keyy, strlen(keyy));

	if (NULL == (ec_group = EC_GROUP_new_by_curve_name(NID_sm2)))
	{
		err = "EC_GROUP_new_by_curve_name failed";
		goto clean_up;
	} 

	if (NULL == (ec_key = EC_KEY_new())) {
		err = "EC_KEY_new failed";
		goto clean_up;
	}

	if ( (EC_KEY_set_group(ec_key, ec_group) != 1 )){
		err = "EC_KEY_set_group failed";
		goto clean_up;
	}

	if (NULL == (pt = EC_POINT_new(ec_group))) {
		err = "EC_POINT_new failed";
		goto clean_up;
	}

	if (!(BN_hex2bn(&kx, keyx) && BN_hex2bn(&ky, keyy))) {
		err = "Public key string to bn failed";
		goto clean_up;
	}

	if ( !EC_POINT_set_affine_coordinates(ec_group, pt, kx, ky, NULL)) {
		err = "EC_POINT_set_affine_coordinates failed";
		goto clean_up;
	}

	if ( !EC_KEY_set_public_key(ec_key, pt)) {
		err ="EC_KEY_set_public_key failed";
		goto clean_up;
	}

	if (NULL == (sm2key = EVP_PKEY_new())) {
		err = "EVP_PKEY_new failed";
		goto clean_up;
	}

	if ( !EVP_PKEY_assign_EC_KEY(sm2key, ec_key)) {
		err = "EVP_PKEY_assign_EC_KEY failed";
		goto clean_up;
	}

	if(!PEM_write_PUBKEY(fp, sm2key)) {
		err = "Error writing public key data in PEM format";
		goto clean_up;
	}

clean_up:
	if (fp)
		fclose(fp);
	if (pt)
		EC_POINT_free(pt);
	if (kx)
		BN_free(kx);
	if (ky)
		BN_free(ky);
	if (ec_key)
		EC_KEY_free(ec_key);
	if (ec_group)
		EC_GROUP_free(ec_group);
	if (sm2key)
		EVP_PKEY_free(sm2key);

	if (err) {
		return luaL_error(L, err);
	}

	return 0;
}
*/

// 从私钥生成证书(单独私钥不能导出证书????)
/*
int lsm2prikey_write(lua_State *L) {
	const char* err = NULL;
	const char* pri_key = luaL_checkstring(L, 1);
	const char* keyname = luaL_checkstring(L, 2);
	EVP_PKEY *sm2key = NULL;
	EC_KEY *ec_key = NULL;
	EC_GROUP *ec_group = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *kp = NULL;

	printf("%s: pri_key: %s len: %lu\n", __func__, pri_key, strlen(pri_key));

	FILE *fp = fopen(keyname, "wb");
	if (!fp) {
		err = "Write file failed after generate SM2 key.";
		goto clean_up;
	}

	if (pri_key && 64 != strlen(pri_key)) {
		err = "Public key length error";
		goto clean_up;
	}

	if (NULL == (ec_group = EC_GROUP_new_by_curve_name(NID_sm2)))
	{
		err = "EC_GROUP_new_by_curve_name failed";
		goto clean_up;
	} 

	if (NULL == (ec_key = EC_KEY_new())) {
		err = "EC_KEY_new failed";
		goto clean_up;
	}

	if ((EC_KEY_set_group(ec_key, ec_group) != 1 )){
		err = "EC_KEY_set_group failed";
		goto clean_up;
	}

	if (!BN_hex2bn(&kp, pri_key)) {
		err = "Private key string to bn failed";
		goto clean_up;
	}

	if (!EC_KEY_set_private_key(ec_key, kp)) {
		err = "EC_KEY_set_private_key failed";
		goto clean_up;
	}

	if (NULL == (sm2key = EVP_PKEY_new())) {
		err = "EVP_PKEY_new failed";
		goto clean_up;
	}

	if ( !EVP_PKEY_assign_EC_KEY(sm2key, ec_key)) {
		err = "EVP_PKEY_assign_EC_KEY failed";
		EVP_PKEY_free(sm2key);
		sm2key = NULL;
		goto clean_up;
	}

	if(!PEM_write_PrivateKey(fp, sm2key, NULL, NULL, 0, 0, NULL)) {
		err = "Error writing private key data in PEM format";
		goto clean_up;
	}

clean_up:
	if (fp)
		fclose(fp);
	if (kp)
		BN_free(kp);
	if (ec_key)
		EC_KEY_free(ec_key);
	if (ec_group)
		EC_GROUP_free(ec_group);
	if (sm2key)
		EVP_PKEY_free(sm2key);
	if (err) {
		return luaL_error(L, err);
	}

	return 0;
}
*/

#endif
