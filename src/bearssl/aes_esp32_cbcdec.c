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

/* see bearssl_block.h */
void
br_aes_esp32_cbcdec_init(br_aes_esp32_cbcdec_keys *ctx,
	const void *key, size_t len)
{
	ctx->vtable = &br_aes_esp32_cbcdec_vtable;
	/* if(32 < len) abort(); */
	memcpy(ctx->key, key, len);
	ctx->len = len;
}

/* see bearssl_block.h */
void
br_aes_esp32_cbcdec_run(const br_aes_esp32_cbcdec_keys *ctx,
	void *iv, void *data, size_t len)
{
	br_aes_esp32_decrypt_cbc(ctx, (unsigned char*)iv, (unsigned char*)data, len);
}

/* see bearssl_block.h */
const br_block_cbcdec_class br_aes_esp32_cbcdec_vtable = {
	sizeof(br_aes_esp32_cbcdec_keys),
	16,
	4,
	(void (*)(const br_block_cbcdec_class **, const void *, size_t))
		&br_aes_esp32_cbcdec_init,
	(void (*)(const br_block_cbcdec_class *const *, void *, void *, size_t))
		&br_aes_esp32_cbcdec_run
};

#endif  // ARDUINO_ARCH_ESP32
