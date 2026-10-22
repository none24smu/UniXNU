#!/usr/bin/env python3
"""Test the KPI adapter with XNU's actual callback types and an OpenSSL backend.

This checks adapter dispatch, context/output bounds, streaming, truncation and
verification under ASan/UBSan. It does not validate the Apple provider or kernel
execution; the built-in provider POST and hardware probes cover those layers.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--xnu-source', required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
header = (args.xnu_source / 'libkern/libkern/crypto/register_crypto.h').read_text()
enum = header.split('__enum_decl(crypto_digest_alg_t, unsigned int, {', 1)[1].split('});', 1)[0]
types = header.split('typedef size_t (*crypto_digest_ctx_size_fn_t)', 1)[1].split('typedef struct crypto_functions', 1)[0]
fields = header.split('// Digest functions', 1)[1].split('} *crypto_functions_t;', 1)[0]
prelude = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#define panic(...) abort()
struct ccdigest_info { size_t output_size; const EVP_MD *(*md)(void); };
struct digest_ctx { EVP_MD_CTX *p; };
struct hmac_ctx { HMAC_CTX *p; };
typedef void *ccdigest_ctx_t;
#define ccdigest_di_size(di) ((void)(di), sizeof(struct digest_ctx))
#define cchmac_di_size(di) ((void)(di), sizeof(struct hmac_ctx))
#define cchmac_di_decl(di, name) (void)(di); struct hmac_ctx name[1]
#define cchmac_di_clear(di, name) cc_clear(sizeof(struct hmac_ctx), name)
static void cc_clear(size_t n, void *p) { OPENSSL_cleanse(p,n); }
static int cc_cmp_safe(size_t n,const void *a,const void *b) { return CRYPTO_memcmp(a,b,n); }
#define DI(name, bytes) static const struct ccdigest_info *cc##name##_di(void) { \
 static const struct ccdigest_info di={bytes,EVP_##name}; return &di; }
DI(md5,16) DI(sha1,20) DI(sha256,32) DI(sha384,48) DI(sha512,64)
static void ccdigest_init(const struct ccdigest_info *di,void *v) {
 struct digest_ctx *c=v; c->p=EVP_MD_CTX_new(); assert(c->p); assert(EVP_DigestInit_ex(c->p,di->md(),NULL)); }
static void ccdigest_update(const struct ccdigest_info *di,void *v,size_t n,const void *p) {
 (void)di; assert(EVP_DigestUpdate(((struct digest_ctx *)v)->p,p,n)); }
static void ccdigest_final(const struct ccdigest_info *di,void *v,unsigned char *out) {
 (void)di; struct digest_ctx *c=v; unsigned n; assert(EVP_DigestFinal_ex(c->p,out,&n)); EVP_MD_CTX_free(c->p); }
static void ccdigest(const struct ccdigest_info *di,size_t n,const void *p,void *out) {
 unsigned len; assert(EVP_Digest(p,n,out,&len,di->md(),NULL)); }
static void cchmac_init(const struct ccdigest_info *di,void *v,size_t n,const void *key) {
 struct hmac_ctx *c=v; c->p=HMAC_CTX_new(); assert(c->p); assert(HMAC_Init_ex(c->p,key,n,di->md(),NULL)); }
static void cchmac_update(const struct ccdigest_info *di,void *v,size_t n,const void *p) {
 (void)di; assert(HMAC_Update(((struct hmac_ctx *)v)->p,p,n)); }
static void cchmac_final(const struct ccdigest_info *di,void *v,unsigned char *out) {
 (void)di; struct hmac_ctx *c=v; unsigned n; assert(HMAC_Final(c->p,out,&n)); HMAC_CTX_free(c->p); }
'''
main = r'''
int main(int argc,char **argv) {
 struct crypto_functions f={0}; cc12377_complete_kpis(&f);
 if(argc>1) {
  unsigned char out[64]; _Alignas(8) unsigned char ctx[32];
  if(!strcmp(argv[1],"context")) f.digest_init_fn(CRYPTO_DIGEST_ALG_SHA1,ctx,0);
  if(!strcmp(argv[1],"alignment")) f.digest_init_fn(CRYPTO_DIGEST_ALG_SHA1,ctx+1,16);
  if(!strcmp(argv[1],"digest")) f.digest_fn(CRYPTO_DIGEST_ALG_SHA1,"abc",3,out,1);
  if(!strcmp(argv[1],"algorithm")) f.digest_ctx_size_fn(CRYPTO_DIGEST_ALG_NONE);
  if(!strcmp(argv[1],"tag")) f.hmac_generate_fn(CRYPTO_DIGEST_ALG_SHA256,"key",3,"abc",3,out,65);
  if(!strcmp(argv[1],"empty-tag")) f.hmac_generate_fn(CRYPTO_DIGEST_ALG_SHA256,"key",3,"abc",3,out,0);
  return 99;
 }
 const EVP_MD *(*mds[])(void)={EVP_md5,EVP_sha1,EVP_sha256,EVP_sha384,EVP_sha512};
 unsigned char data[2000],key[131]; memset(key,0xaa,sizeof(key));
 for(size_t i=0;i<sizeof(data);i++)data[i]=i;
 for(int alg=1;alg<=5;alg++) for(size_t len=0;len<=2000;len+=(len==0?3:1997)) {
  unsigned char expected[64],out[80]; unsigned size;
  _Alignas(8) unsigned char ctx[32];
  assert(EVP_Digest(data,len,expected,&size,mds[alg-1](),NULL));
  memset(out,0xa5,sizeof(out)); f.digest_fn(alg,data,len,out,size);
  assert(!memcmp(out,expected,size)); assert(out[size]==0xa5);
  f.digest_init_fn(alg,ctx,f.digest_ctx_size_fn(alg));
  f.digest_update_fn(alg,ctx,sizeof(ctx),data,len/2);
  f.digest_update_fn(alg,ctx,sizeof(ctx),data+len/2,len-len/2);
  f.digest_final_fn(alg,ctx,sizeof(ctx),out,size); assert(!memcmp(out,expected,size));
  assert(HMAC(mds[alg-1](),key,sizeof(key),data,len,expected,&size));
  for(size_t tag=1;tag<=size;tag++) {
   memset(out,0xa5,sizeof(out)); f.hmac_generate_fn(alg,key,sizeof(key),data,len,out,tag);
   assert(!memcmp(out,expected,tag)); assert(out[tag]==0xa5);
   assert(f.hmac_verify_fn(alg,key,sizeof(key),data,len,out,tag));
   out[0]^=1; assert(!f.hmac_verify_fn(alg,key,sizeof(key),data,len,out,tag));
  }
  f.hmac_init_fn(alg,ctx,f.hmac_ctx_size_fn(alg),key,sizeof(key));
  f.hmac_update_fn(alg,ctx,sizeof(ctx),data,len/2);
  f.hmac_update_fn(alg,ctx,sizeof(ctx),data+len/2,len-len/2);
  f.hmac_final_generate_fn(alg,ctx,sizeof(ctx),out,size); assert(!memcmp(out,expected,size));
  f.hmac_init_fn(alg,ctx,sizeof(ctx),key,sizeof(key));
  f.hmac_update_fn(alg,ctx,sizeof(ctx),data,len);
  assert(f.hmac_final_verify_fn(alg,ctx,sizeof(ctx),expected,size));
 }
 puts("KPI adapter: five digests, streaming, all HMAC truncation lengths and verification passed");
}
'''
code = (prelude + '\ntypedef enum {' + enum + '} crypto_digest_alg_t;\n'
        + 'typedef size_t (*crypto_digest_ctx_size_fn_t)' + types
        + '\nstruct crypto_functions { void (*ccdigest_final_fn)(const struct ccdigest_info *,ccdigest_ctx_t,void *);\n'
        + fields + '};\n#include "' + str(root/'scripts/corecrypto-12377-kpi.h') + '"\n' + main)
with tempfile.TemporaryDirectory(prefix='crypto-kpi-') as tmp:
    p=Path(tmp); (p/'test.c').write_text(code)
    subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations',
                    '-fsanitize=address,undefined',str(p/'test.c'),'-lcrypto','-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
    for case in ['context','alignment','digest','algorithm','tag','empty-tag']:
        result=subprocess.run([str(p/'test'),case],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if result.returncode != -6:
            raise SystemExit(f'{case}: expected abort, got {result.returncode}: {result.stderr.decode()}')
    print('Invalid context, alignment, algorithm, digest length and HMAC lengths rejected')
