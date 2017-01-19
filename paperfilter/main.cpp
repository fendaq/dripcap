#include "session_item_value_wrapper.hpp"
#include "session_item_wrapper.hpp"
#include "session_large_buffer_wrapper.hpp"
#include "session_layer_wrapper.hpp"
#include "session_packet_wrapper.hpp"
#include "session_wrapper.hpp"
#include <nan.h>

using namespace v8;

int doit(char *text, char *key, char *iv);

void Init(v8::Local<v8::Object> exports) {
  SessionPacketWrapper::Init(exports);
  SessionLayerWrapper::Init(exports);
  SessionItemWrapper::Init(exports);
  SessionItemValueWrapper::Init(exports);
  SessionLargeBufferWrapper::Init(exports);
  SessionWrapper::Init(exports);
  doit("a", "b", "c");
}

NODE_MODULE(paperfilter, Init)

#include <cstdio>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#define BUFSIZE 256

int doit(char *text, char *key, char *iv) {
  int outlen, inlen;

  char inbuf[BUFSIZE], outbuf[BUFSIZE];

  strcpy(inbuf, text);

  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);

  EVP_EncryptInit_ex(&ctx, EVP_aes_128_cfb8(), NULL, (unsigned char*)key, (unsigned char*)iv);

  int i = 0;
  int n = strlen(text);
  char *p = outbuf;
  for (i; i < n; i++) {

    if (!EVP_EncryptUpdate(&ctx, (unsigned char*)p, &outlen, (unsigned char*)&inbuf[i], 1))
      return 0;
    p += outlen;
  }

  if (!EVP_EncryptFinal(&ctx, (unsigned char*)p, &outlen))
    return 0;
  p += outlen;

  EVP_CIPHER_CTX_cleanup(&ctx);

  outlen = p - outbuf;
  for (n = 0; n < outlen; n++)
    printf("%c", outbuf[n] & 0xff);
}
