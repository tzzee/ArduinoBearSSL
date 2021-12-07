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

#include "pem_to_trust_anchors.h"


/*
 * malloc() wrapper:
 * -- If len is 0, then NULL is returned.
 * -- If len is non-zero, and allocation fails, then an error message is
 *    printed and the process exits with an error code.
 */
void *xmalloc(size_t len);

/*
 * free() wrapper, meant to release blocks allocated with xmalloc().
 */
void xfree(void *buf);

/*
 * Duplicate a character string into a newly allocated block.
 */
char *xstrdup(const void *src);

/*
 * Allocate a new block with the provided length, filled with a copy
 * of exactly that many bytes starting at address 'src'.
 */
void *xblobdup(const void *src, size_t len);

/*
 * Duplicate a public key, into newly allocated blocks. The returned
 * key must be later on released with xfreepkey().
 */
br_x509_pkey *xpkeydup(const br_x509_pkey *pk);

/*
 * Release a public key that was allocated with xpkeydup(). If pk is NULL,
 * this function does nothing.
 */
void xfreepkey(br_x509_pkey *pk);

/*
 * Macros for growable arrays.
 */

/*
 * Make a structure type for a vector of 'type'.
 */
#define VECTOR(type)   struct { \
    type *buf; \
    size_t ptr, len; \
  }

/*
 * Constant initialiser for a vector.
 */
#define VEC_INIT   { 0, 0, 0 }

/*
 * Clear a vector.
 */
#define VEC_CLEAR(vec)   do { \
    xfree((vec).buf); \
    (vec).buf = NULL; \
    (vec).ptr = 0; \
    (vec).len = 0; \
  } while (0)

/*
 * Clear a vector, first calling the provided function on each vector
 * element.
 */
#define VEC_CLEAREXT(vec, fun)   do { \
    size_t vec_tmp; \
    for (vec_tmp = 0; vec_tmp < (vec).ptr; vec_tmp ++) { \
      (fun)(&(vec).buf[vec_tmp]); \
    } \
    VEC_CLEAR(vec); \
  } while (0)

/*
 * Add a value at the end of a vector.
 */
#define VEC_ADD(vec, x)   do { \
    (vec).buf = (typeof((vec).buf))vector_expand((vec).buf, sizeof *((vec).buf), \
      &(vec).ptr, &(vec).len, 1); \
    (vec).buf[(vec).ptr ++] = (x); \
  } while (0)

/*
 * Add several values at the end of a vector.
 */
#define VEC_ADDMANY(vec, xp, num)   do { \
    size_t vec_num = (num); \
    (vec).buf = (typeof((vec).buf))vector_expand((vec).buf, sizeof *((vec).buf), \
      &(vec).ptr, &(vec).len, vec_num); \
    memcpy((vec).buf + (vec).ptr, \
      (xp), vec_num * sizeof *((vec).buf)); \
    (vec).ptr += vec_num; \
  } while (0)

/*
 * Access a vector element by index. This is a lvalue, and can be modified.
 */
#define VEC_ELT(vec, idx)   ((vec).buf[idx])

/*
 * Get current vector length.
 */
#define VEC_LEN(vec)   ((vec).ptr)

/*
 * Copy all vector elements into a newly allocated block.
 */
#define VEC_TOARRAY(vec)    xblobdup((vec).buf, sizeof *((vec).buf) * (vec).ptr)

/*
 * Internal function used to handle memory allocations for vectors.
 */
void *vector_expand(void *buf,
  size_t esize, size_t *ptr, size_t *len, size_t extra);

/*
 * Type for a vector of bytes.
 */
typedef VECTOR(unsigned char) bvector;

/*
 * Compare two strings for equality; returned value is 1 if the strings
 * are to be considered equal, 0 otherwise. Comparison is case-insensitive
 * (ASCII letters only) and skips some characters (all whitespace, defined
 * as ASCII codes 0 to 32 inclusive, and also '-', '_', '.', '/', '+' and
 * ':').
 */
int eqstr(const char *s1, const char *s2);

/*
 * Type for a named blob (the 'name' is a normalised PEM header name).
 */
typedef struct {
  char *name;
  unsigned char *data;
  size_t data_len;
} pem_object;

/*
 * Release the contents of a named blob (buffer and name).
 */
void free_pem_object_contents(pem_object *po);

/*
 * Decode a buffer as a PEM file, and return all objects. On error, NULL
 * is returned and an error message is printed. Absence of any object
 * is an error.
 *
 * The returned array is terminated by a dummy object whose 'name' is
 * NULL. The number of objects (not counting the dummy terminator) is
 * written in '*num'.
 */
pem_object *decode_pem(const void *src, size_t len, size_t *num);

/*
 * Get the certificate(s) from a file. This accepts both a single
 * DER-encoded certificate, and a text file that contains
 * PEM-encoded certificates (and possibly other objects, which are
 * then ignored).
 *
 * On decoding error, or if the file turns out to contain no certificate
 * at all, then an error message is printed and NULL is returned.
 *
 * The returned array, and all referenced buffers, are allocated with
 * xmalloc() and must be released by the caller. The returned array
 * ends with a dummy entry whose 'data' field is NULL.
 * The number of decoded certificates (not counting the dummy entry)
 * is written into '*num'.
 */
br_x509_certificate *read_certificates(const unsigned char *buf, const size_t len, size_t *num);

/*
 * Release certificates. This releases all certificate data arrays,
 * and the whole array as well.
 */
void free_certificates(br_x509_certificate *certs, size_t num);

/*
 * Interpret a certificate as a trust anchor. The trust anchor is
 * newly allocated with xmalloc() and the caller must release it.
 * On decoding error, an error message is printed, and this function
 * returns NULL.
 */
br_x509_trust_anchor *certificate_to_trust_anchor(br_x509_certificate *xc);

/*
 * Type for a vector of trust anchors.
 */
typedef VECTOR(br_x509_trust_anchor) anchor_list;

/*
 * Release contents for a trust anchor (assuming they were dynamically
 * allocated with xmalloc()). The structure itself is NOT released.
 */
void free_ta_contents(br_x509_trust_anchor *ta);

/*
 * Decode certificates from a file and interpret them as trust anchors.
 * The trust anchors are added to the provided list. The number of found
 * anchors is returned; on error, 0 is returned (finding no anchor at
 * all is considered an error). An appropriate error message is displayed.
 */
size_t read_trust_anchors(anchor_list *dst, const unsigned char* ca_pem, const size_t ca_len);

static int
is_ign(int c)
{
  if (c == 0) {
    return 0;
  }
  if (c <= 32 || c == '-' || c == '_' || c == '.'
    || c == '/' || c == '+' || c == ':')
  {
    return 1;
  }
  return 0;
}

/*
 * Get next non-ignored character, normalised:
 *    ASCII letters are converted to lowercase
 *    control characters, space, '-', '_', '.', '/', '+' and ':' are ignored
 * A terminating zero is returned as 0.
 */
static int
next_char(const char **ps, const char *limit)
{
  for (;;) {
    int c;

    if (*ps == limit) {
      return 0;
    }
    c = *(*ps) ++;
    if (c == 0) {
      return 0;
    }
    if (c >= 'A' && c <= 'Z') {
      c += 'a' - 'A';
    }
    if (!is_ign(c)) {
      return c;
    }
  }
}

/*
 * Partial string equality comparison, with normalisation.
 */
static int
eqstr_chunk(const char *s1, size_t s1_len, const char *s2, size_t s2_len)
{
  const char *lim1, *lim2;

  lim1 = s1 + s1_len;
  lim2 = s2 + s2_len;
  for (;;) {
    int c1, c2;

    c1 = next_char(&s1, lim1);
    c2 = next_char(&s2, lim2);
    if (c1 != c2) {
      return 0;
    }
    if (c1 == 0) {
      return 1;
    }
  }
}

/* see brssl.h */
int
eqstr(const char *s1, const char *s2)
{
  return eqstr_chunk(s1, strlen(s1), s2, strlen(s2));
}

/* see brssl.h */
void *
xmalloc(size_t len)
{
  void *buf;

  if (len == 0) {
    return NULL;
  }
  buf = malloc(len);
  if (buf == NULL) {
    fprintf(stderr, "ERROR: could not allocate %lu byte(s)\n",
      (unsigned long)len);
    exit(EXIT_FAILURE);
  }
  return buf;
}

/* see brssl.h */
void
xfree(void *buf)
{
  if (buf != NULL) {
    free(buf);
  }
}

/* see brssl.h */
void *
xblobdup(const void *src, size_t len)
{
  void *buf;

  buf = xmalloc(len);
  memcpy(buf, src, len);
  return buf;
}

/* see brssl.h */
char *
xstrdup(const void *src)
{
  return (char *)xblobdup((const char*)src, strlen((const char*)src) + 1);
}

static void
vblob_append(void *cc, const void *data, size_t len)
{
  bvector *bv;

  bv = (bvector*)cc;
  VEC_ADDMANY(*bv, data, len);
}

void *
vector_expand(void *buf,
  size_t esize, size_t *ptr, size_t *len, size_t extra)
{
  size_t nlen;
  void *nbuf;

  if (*len - *ptr >= extra) {
    return buf;
  }
  nlen = (*len << 1);
  if (nlen - *ptr < extra) {
    nlen = extra + *ptr;
    if (nlen < 8) {
      nlen = 8;
    }
  }
  nbuf = xmalloc(nlen * esize);
  if (buf != NULL) {
    memcpy(nbuf, buf, *len * esize);
    xfree(buf);
  }
  *len = nlen;
  return nbuf;
}




static void
dn_append(void *ctx, const void *buf, size_t len)
{
  VEC_ADDMANY(*(bvector *)ctx, buf, len);
}

static int
certificate_to_trust_anchor_inner(br_x509_trust_anchor *ta,
  br_x509_certificate *xc)
{
  br_x509_decoder_context dc;
  bvector vdn = VEC_INIT;
  br_x509_pkey *pk;

  br_x509_decoder_init(&dc, dn_append, &vdn);
  br_x509_decoder_push(&dc, xc->data, xc->data_len);
  pk = br_x509_decoder_get_pkey(&dc);
  if (pk == NULL) {
    fprintf(stderr, "ERROR: CA decoding failed with error %d\n",
      br_x509_decoder_last_error(&dc));
    VEC_CLEAR(vdn);
    return -1;
  }
  ta->dn.data = (unsigned char*)VEC_TOARRAY(vdn);
  ta->dn.len = VEC_LEN(vdn);
  VEC_CLEAR(vdn);
  ta->flags = 0;
  if (br_x509_decoder_isCA(&dc)) {
    ta->flags |= BR_X509_TA_CA;
  }
  switch (pk->key_type) {
  case BR_KEYTYPE_RSA:
    ta->pkey.key_type = BR_KEYTYPE_RSA;
    ta->pkey.key.rsa.n = (unsigned char*)xblobdup(pk->key.rsa.n, pk->key.rsa.nlen);
    ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
    ta->pkey.key.rsa.e = (unsigned char*)xblobdup(pk->key.rsa.e, pk->key.rsa.elen);
    ta->pkey.key.rsa.elen = pk->key.rsa.elen;
    break;
  case BR_KEYTYPE_EC:
    ta->pkey.key_type = BR_KEYTYPE_EC;
    ta->pkey.key.ec.curve = pk->key.ec.curve;
    ta->pkey.key.ec.q = (unsigned char*)xblobdup(pk->key.ec.q, pk->key.ec.qlen);
    ta->pkey.key.ec.qlen = pk->key.ec.qlen;
    break;
  default:
    fprintf(stderr, "ERROR: unsupported public key type in CA\n");
    xfree(ta->dn.data);
    return -1;
  }
  return 0;
}

/* see brssl.h */
void
free_pem_object_contents(pem_object *po)
{
  if (po != NULL) {
    xfree(po->name);
    xfree(po->data);
  }
}

/* see brssl.h */
pem_object *
decode_pem(const void *src, size_t len, size_t *num)
{
  VECTOR(pem_object) pem_list = VEC_INIT;
  br_pem_decoder_context pc;
  pem_object po, *pos;
  const unsigned char *buf;
  bvector bv = VEC_INIT;
  int inobj;
  int extra_nl;

  *num = 0;
  br_pem_decoder_init(&pc);
  buf = (const unsigned char *)src;
  inobj = 0;
  po.name = NULL;
  po.data = NULL;
  po.data_len = 0;
  extra_nl = 1;
  while (len > 0) {
    size_t tlen;

    tlen = br_pem_decoder_push(&pc, buf, len);
    buf += tlen;
    len -= tlen;
    switch (br_pem_decoder_event(&pc)) {

    case BR_PEM_BEGIN_OBJ:
      po.name = xstrdup(br_pem_decoder_name(&pc));
      br_pem_decoder_setdest(&pc, vblob_append, &bv);
      inobj = 1;
      break;

    case BR_PEM_END_OBJ:
      if (inobj) {
        po.data = (unsigned char*)VEC_TOARRAY(bv);
        po.data_len = VEC_LEN(bv);
        VEC_ADD(pem_list, po);
        VEC_CLEAR(bv);
        po.name = NULL;
        po.data = NULL;
        po.data_len = 0;
        inobj = 0;
      }
      break;

    case BR_PEM_ERROR:
      xfree(po.name);
      VEC_CLEAR(bv);
      fprintf(stderr, "invalid PEM encoding\n");
      VEC_CLEAREXT(pem_list, &free_pem_object_contents);
      return NULL;
    }

    /*
     * We add an extra newline at the end, in order to
     * support PEM files that lack the newline on their last
     * line (this is somwehat invalid, but PEM format is not
     * standardised and such files do exist in the wild, so
     * we'd better accept them).
     */
    if (len == 0 && extra_nl) {
      extra_nl = 0;
      buf = (const unsigned char *)"\n";
      len = 1;
    }
  }
  if (inobj) {
    fprintf(stderr, "ERROR: unfinished PEM object\n");
    xfree(po.name);
    VEC_CLEAR(bv);
    VEC_CLEAREXT(pem_list, &free_pem_object_contents);
    return NULL;
  }

  *num = VEC_LEN(pem_list);
  VEC_ADD(pem_list, po);
  pos = (pem_object*)VEC_TOARRAY(pem_list);
  VEC_CLEAR(pem_list);
  return pos;
}

/* see brssl.h */
br_x509_certificate *
read_certificates(const unsigned char *buf, const size_t len, size_t *num)
{
  VECTOR(br_x509_certificate) cert_list = VEC_INIT;
  pem_object *pos;
  size_t u, num_pos;
  br_x509_certificate *xcs;
  br_x509_certificate dummy;

  *num = 0;
  pos = decode_pem(buf, len, &num_pos);
  if (pos == NULL) {
    return NULL;
  }
  for (u = 0; u < num_pos; u ++) {
    if (eqstr(pos[u].name, "CERTIFICATE")
      || eqstr(pos[u].name, "X509 CERTIFICATE"))
    {
      br_x509_certificate xc;

      xc.data = pos[u].data;
      xc.data_len = pos[u].data_len;
      pos[u].data = NULL;
      VEC_ADD(cert_list, xc);
    }
  }
  for (u = 0; u < num_pos; u ++) {
    free_pem_object_contents(&pos[u]);
  }
  xfree(pos);

  if (VEC_LEN(cert_list) == 0) {
    fprintf(stderr, "ERROR: no certificate\n");
    return NULL;
  }
  *num = VEC_LEN(cert_list);
  dummy.data = NULL;
  dummy.data_len = 0;
  VEC_ADD(cert_list, dummy);
  xcs = (br_x509_certificate*)VEC_TOARRAY(cert_list);
  VEC_CLEAR(cert_list);
  return xcs;
}


/* see brssl.h */
void
free_certificates(br_x509_certificate *certs, size_t num)
{
  size_t u;

  for (u = 0; u < num; u ++) {
    xfree(certs[u].data);
  }
  xfree(certs);
}

/* see brssl.h */
void
free_ta_contents(br_x509_trust_anchor *ta)
{
  xfree(ta->dn.data);
  switch (ta->pkey.key_type) {
  case BR_KEYTYPE_RSA:
    xfree(ta->pkey.key.rsa.n);
    xfree(ta->pkey.key.rsa.e);
    break;
  case BR_KEYTYPE_EC:
    xfree(ta->pkey.key.ec.q);
    break;
  }
}

size_t
read_trust_anchors(anchor_list *dst, const unsigned char* ca_pem, const size_t ca_len)
{
  br_x509_certificate *xcs;
  anchor_list tas = VEC_INIT;
  size_t u, num;

  xcs = read_certificates(ca_pem, ca_len, &num);
  if (xcs == NULL) {
    return 0;
  }
  for (u = 0; u < num; u ++) {
    br_x509_trust_anchor ta;

    if (certificate_to_trust_anchor_inner(&ta, &xcs[u]) < 0) {
      VEC_CLEAREXT(tas, free_ta_contents);
      free_certificates(xcs, num);
      return 0;
    }
    VEC_ADD(tas, ta);
  }
  VEC_ADDMANY(*dst, &VEC_ELT(tas, 0), num);
  VEC_CLEAR(tas);
  free_certificates(xcs, num);
  return num;
}

void free_trust_anchors(br_x509_trust_anchor* tAs, int numTAs) {
  anchor_list tas = { tAs, 0, numTAs };
  VEC_CLEAREXT(tas, free_ta_contents);
}

br_x509_trust_anchor* from_pem_to_trust_anchors(const char* ca_pem, size_t ca_len, int *num) {
  anchor_list tas = VEC_INIT;
  size_t len1, len2;
  len1 = VEC_LEN(tas);
  if (read_trust_anchors(&tas, (const unsigned char*)ca_pem, ca_len) == 0) {
    goto ta_exit_error;
  }
  len2 = VEC_LEN(tas) - len1;
  *num = VEC_LEN(tas);
  return &VEC_ELT(tas, 0);
ta_exit_error:
  *num = 0;
  VEC_CLEAREXT(tas, free_ta_contents);
  return NULL;
}