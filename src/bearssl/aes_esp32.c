/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 * Copyright (c) 2021 Kenji Takahashi
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if defined(ARDUINO_ARCH_ESP32) && !ARDUINO_ARCH_ESP32_HW_ACCELERATED_AES_DISABLED
#include "inner.h"
#include <hwcrypto/aes.h>


/* see inner.h */
void
br_aes_esp32_encrypt_cbc(const br_aes_esp32_cbcenc_keys *ctx, unsigned char *iv, unsigned char *data, size_t len){
	esp_aes_context esp_aes_ctx;
	esp_aes_init(&esp_aes_ctx);
	esp_aes_setkey(&esp_aes_ctx, ctx->key, ctx->len*8);
	esp_aes_crypt_cbc(&esp_aes_ctx, ESP_AES_ENCRYPT, len, iv, data, data);
	esp_aes_free(&esp_aes_ctx );
}

/* see inner.h */
void
br_aes_esp32_decrypt_cbc(const br_aes_esp32_cbcdec_keys *ctx, unsigned char *iv, unsigned char *data, size_t len){
	esp_aes_context esp_aes_ctx;
	esp_aes_init(&esp_aes_ctx);
	esp_aes_setkey(&esp_aes_ctx, ctx->key, ctx->len*8);
	esp_aes_crypt_cbc(&esp_aes_ctx, ESP_AES_DECRYPT, len, iv, data, data);
	esp_aes_free(&esp_aes_ctx);
}

/* see inner.h */
uint32_t
br_aes_esp32_crypt_ctr(const br_aes_esp32_ctr_keys *ctx, unsigned char *ctr, uint32_t cc, unsigned char *data, size_t len){
	uint32_t nc_off = 0;
	unsigned char stream_block[16];
	esp_aes_context esp_aes_ctx;
	esp_aes_init(&esp_aes_ctx);
	esp_aes_setkey(&esp_aes_ctx, ctx->key, ctx->len*8);
	esp_aes_crypt_ctr(&esp_aes_ctx, len, &nc_off, ctr, stream_block, data, data);
	esp_aes_free(&esp_aes_ctx);
	cc += len/16;
	return cc;
}
#endif  // ARDUINO_ARCH_ESP32
