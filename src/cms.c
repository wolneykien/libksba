/* cms.c - cryptographic message syntax main functions
 * Copyright (C) 2001, 2003, 2004, 2008, 2012, 2020 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * KSBA is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

/* References:
 * RFC-5652 := Cryptographic Message Syntax (CMS) (aka STD0070)
 * SPHINX   := CMS profile developed by the German BSI.
 *             (see also https://lwn.net/2001/1011/a/german-smime.php3)
 * PKCS#7   := Original specification of CMS
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "util.h"

#include "cms.h"
#include "convert.h"
#include "keyinfo.h"
#include "der-encoder.h"
#include "ber-help.h"
#include "sexp-parse.h"
#include "cert.h"
#include "der-builder.h"


static gpg_error_t ct_parse_data (ksba_cms_t cms);
static gpg_error_t ct_parse_signed_data (ksba_cms_t cms);
static gpg_error_t ct_parse_enveloped_data (ksba_cms_t cms);
static gpg_error_t ct_parse_digested_data (ksba_cms_t cms);
static gpg_error_t ct_parse_encrypted_data (ksba_cms_t cms);
static gpg_error_t ct_build_data (ksba_cms_t cms);
static gpg_error_t ct_build_signed_data (ksba_cms_t cms);
static gpg_error_t ct_build_enveloped_data (ksba_cms_t cms);
static gpg_error_t ct_build_digested_data (ksba_cms_t cms);
static gpg_error_t ct_build_encrypted_data (ksba_cms_t cms);

static struct {
  const char *oid;
  ksba_content_type_t ct;
  gpg_error_t (*parse_handler)(ksba_cms_t);
  gpg_error_t (*build_handler)(ksba_cms_t);
} content_handlers[] = {
  {  "1.2.840.113549.1.7.1", KSBA_CT_DATA,
     ct_parse_data   , ct_build_data                  },
  {  "1.2.840.113549.1.7.2", KSBA_CT_SIGNED_DATA,
     ct_parse_signed_data   , ct_build_signed_data    },
  {  "1.2.840.113549.1.7.3", KSBA_CT_ENVELOPED_DATA,
     ct_parse_enveloped_data, ct_build_enveloped_data },
  {  "1.2.840.113549.1.7.5", KSBA_CT_DIGESTED_DATA,
     ct_parse_digested_data , ct_build_digested_data  },
  {  "1.2.840.113549.1.7.6", KSBA_CT_ENCRYPTED_DATA,
     ct_parse_encrypted_data, ct_build_encrypted_data },
  {  "1.2.840.113549.1.9.16.1.2", KSBA_CT_AUTH_DATA   },
  {  "1.3.6.1.4.1.311.2.1.4", KSBA_CT_SPC_IND_DATA_CTX,
     ct_parse_data   , ct_build_data                  },
  {  "1.3.6.1.4.1.11591.2.3.1", KSBA_CT_OPENPGP_KEYBLOCK,
     ct_parse_data   , ct_build_data                  },
  { NULL }
};

static const char oidstr_contentType[] = "1.2.840.113549.1.9.3";
/*static char oid_contentType[9] = "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x03";*/

static const char oidstr_messageDigest[] = "1.2.840.113549.1.9.4";
static const char oid_messageDigest[9] ="\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04";

static const char oidstr_signingTime[] = "1.2.840.113549.1.9.5";
static const char oid_signingTime[9] = "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x05";

static const char oidstr_smimeCapabilities[] = "1.2.840.113549.1.9.15";



#if 0 /* Set to 1 to use this debug helper.  */
static void
log_sexp (const char *text, ksba_const_sexp_t p)
{
  int level = 0;

  gpgrt_log_debug ("%s: ", text);
  if (!p)
    gpgrt_log_printf ("[none]");
  else
    {
      for (;;)
        {
          if (*p == '(')
            {
              gpgrt_log_printf ("%c", *p);
              p++;
              level++;
            }
          else if (*p == ')')
            {
              gpgrt_log_printf ("%c", *p);
              p++;
              if (--level <= 0 )
                return;
            }
          else if (!digitp (p))
            {
              gpgrt_log_printf ("[invalid s-exp]");
              return;
            }
          else
            {
              char *endp;
              const unsigned char *s;
              unsigned long len, n;

              len = strtoul (p, &endp, 10);
              p = endp;
              if (*p != ':')
                {
                  gpgrt_log_printf ("[invalid s-exp]");
                  return;
                }
              p++;
              for (s=p,n=0; n < len; n++, s++)
                if ( !((*s >= 'a' && *s <= 'z')
                       || (*s >= 'A' && *s <= 'Z')
                       || (*s >= '0' && *s <= '9')
                       || *s == '-' || *s == '.'))
                  break;
              if (n < len)
                {
                  gpgrt_log_printf ("#");
                  for (n=0; n < len; n++, p++)
                    gpgrt_log_printf ("%02X", *p);
                  gpgrt_log_printf ("#");
                }
              else
                {
                  for (n=0; n < len; n++, p++)
                    gpgrt_log_printf ("%c", *p);
                }
            }
        }
    }
  gpgrt_log_printf ("\n");
}
#endif /* debug helper */


/* Helper for read_and_hash_cont().  */
static gpg_error_t
read_hash_block (ksba_cms_t cms, unsigned long nleft)
{
  gpg_error_t err;
  char buffer[4096];
  size_t n, nread;

  while (nleft)
    {
      n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
      err = ksba_reader_read (cms->reader, buffer, n, &nread);
      if (err)
        return err;
      nleft -= nread;
      if (cms->hash_fnc)
        cms->hash_fnc (cms->hash_fnc_arg, buffer, nread);
      if (cms->writer)
        err = ksba_writer_write (cms->writer, buffer, nread);
      if (err)
        return err;
    }
  return 0;
}


/* Copy all the bytes from the reader to the writer and hash them if a
   a hash function has been set.  The writer may be NULL to just do
   the hashing */
static gpg_error_t
read_and_hash_cont (ksba_cms_t cms)
{
  gpg_error_t err = 0;
  unsigned long nleft;
  struct tag_info ti;

  if (cms->inner_cont_ndef)
    {
      for (;;)
        {
          err = _ksba_ber_read_tl (cms->reader, &ti);
          if (err)
            return err;

          if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
              && !ti.is_constructed)
            { /* next chunk */
              nleft = ti.length;
              err = read_hash_block (cms, nleft);
              if (err)
                return err;
            }
          else if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
                   && ti.is_constructed)
            { /* next chunk is constructed */
              for (;;)
                {
                  err = _ksba_ber_read_tl (cms->reader, &ti);
                  if (err)
                    return err;
                  if (ti.class == CLASS_UNIVERSAL
                      && ti.tag == TYPE_OCTET_STRING
                      && !ti.is_constructed)
                    {
                      nleft = ti.length;
                      err = read_hash_block (cms, nleft);
                      if (err)
                        return err;
                    }
                  else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                           && !ti.is_constructed)
                    break; /* ready with this chunk */
                  else
                    return gpg_error (GPG_ERR_ENCODING_PROBLEM);
                }
            }
          else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                   && !ti.is_constructed)
            return 0; /* ready */
          else
            return gpg_error (GPG_ERR_ENCODING_PROBLEM);
        }
    }
  else
    {
      /* This is basically the same as above but we allow for
         arbitrary types.  Not sure whether it is really needed but
         right in the beginning of gnupg 1.9 we had at least one
         message with didn't used octet strings.  Not ethat we don't
         do proper NLEFT checking but well why should we validate
         these things?  Well, it might be nice to have such a feature
         but then we should write a more general mechanism to do
         that.  */
      nleft = cms->inner_cont_len;
      /* First read the octet string but allow all types here */
      err = _ksba_ber_read_tl (cms->reader, &ti);
      if (err)
        return err;
      if (nleft < ti.nhdr)
        return gpg_error (GPG_ERR_ENCODING_PROBLEM);
      nleft -= ti.nhdr;

      if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
          && ti.is_constructed)
        { /* Next chunk is constructed */
          for (;;)
            {
              err = _ksba_ber_read_tl (cms->reader, &ti);
              if (err)
                return err;
              if (ti.class == CLASS_UNIVERSAL
                  && ti.tag == TYPE_OCTET_STRING
                  && !ti.is_constructed)
                {
                  nleft = ti.length;
                  err = read_hash_block (cms, nleft);
                  if (err)
                    return err;
                }
              else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                       && !ti.is_constructed)
                break; /* Ready with this chunk */
              else
                return gpg_error (GPG_ERR_ENCODING_PROBLEM);
            }
        }
      else if (ti.class == CLASS_UNIVERSAL && !ti.tag
               && !ti.is_constructed)
        return 0; /* ready */
      else
        {
          err = read_hash_block (cms, nleft);
          if (err)
            return err;
        }
    }
  return 0;
}



/* Copy all the encrypted bytes from the reader to the writer.
   Handles indefinite length encoding */
static gpg_error_t
read_encrypted_cont (ksba_cms_t cms)
{
  gpg_error_t err = 0;
  unsigned long nleft;
  char buffer[4096];
  size_t n, nread;

  if (cms->inner_cont_ndef)
    {
      struct tag_info ti;

      /* fixme: this ist mostly a duplicate of the code in
         read_and_hash_cont(). */
      for (;;)
        {
          err = _ksba_ber_read_tl (cms->reader, &ti);
          if (err)
            return err;

          if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
              && !ti.is_constructed)
            { /* next chunk */
              nleft = ti.length;
              while (nleft)
                {
                  n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
                  err = ksba_reader_read (cms->reader, buffer, n, &nread);
                  if (err)
                    return err;
                  nleft -= nread;
                  err = ksba_writer_write (cms->writer, buffer, nread);
                  if (err)
                    return err;
                }
            }
          else if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
                   && ti.is_constructed)
            { /* next chunk is constructed */
              for (;;)
                {
                  err = _ksba_ber_read_tl (cms->reader, &ti);
                  if (err)
                    return err;
                  if (ti.class == CLASS_UNIVERSAL
                      && ti.tag == TYPE_OCTET_STRING
                      && !ti.is_constructed)
                    {
                      nleft = ti.length;
                      while (nleft)
                        {
                          n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
                          err = ksba_reader_read (cms->reader, buffer, n, &nread);
                          if (err)
                            return err;
                          nleft -= nread;
                          if (cms->writer)
                            err = ksba_writer_write (cms->writer, buffer, nread);
                          if (err)
                            return err;
                        }
                    }
                  else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                           && !ti.is_constructed)
                    break; /* ready with this chunk */
                  else
                    return gpg_error (GPG_ERR_ENCODING_PROBLEM);
                }
            }
          else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                   && !ti.is_constructed)
            return 0; /* ready */
          else
            return gpg_error (GPG_ERR_ENCODING_PROBLEM);
        }
    }
  else
    {
      nleft = cms->inner_cont_len;
      while (nleft)
        {
          n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
          err = ksba_reader_read (cms->reader, buffer, n, &nread);
          if (err)
            return err;
          nleft -= nread;
          err = ksba_writer_write (cms->writer, buffer, nread);
          if (err)
            return err;
        }
    }
  return 0;
}

/* copy data from reader to writer.  Assume that it is an octet string
   and insert undefinite length headers where needed */
static gpg_error_t
write_encrypted_cont (ksba_cms_t cms)
{
  gpg_error_t err = 0;
  char buffer[4096];
  size_t nread;

  /* we do it the simple way: the parts are made up from the chunks we
     got from the read function.

     Fixme: We should write the tag here, and write a definite length
     header if everything fits into our local buffer.  Actually pretty
     simple to do, but I am too lazy right now. */
  while (!(err = ksba_reader_read (cms->reader, buffer,
                                   sizeof buffer, &nread)) )
    {
      err = _ksba_ber_write_tl (cms->writer, TYPE_OCTET_STRING,
                                CLASS_UNIVERSAL, 0, nread);
      if (!err)
        err = ksba_writer_write (cms->writer, buffer, nread);
    }
  if (gpg_err_code (err) == GPG_ERR_EOF) /* write the end tag */
      err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);

  return err;
}


/* Figure out whether the data read from READER is a CMS object and
   return its content type.  This function does only peek at the
   READER and tries to identify the type with best effort.  Because of
   the ubiquity of the stupid and insecure pkcs#12 format, the
   function will also identify those files and return KSBA_CT_PKCS12;
   there is and will be no other pkcs#12 support in this library. */
ksba_content_type_t
ksba_cms_identify (ksba_reader_t reader)
{
  struct tag_info ti;
  unsigned char buffer[24];
  const unsigned char*p;
  size_t n, count;
  char *oid;
  int i;
  int maybe_p12 = 0;

  if (!reader)
    return KSBA_CT_NONE; /* oops */

  /* This is a common example of a CMS object - it is obvious that we
     only need to read a few bytes to get to the OID:
  30 82 0B 59 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 0B 4A 30 82 0B 46 02
  ----------- ++++++++++++++++++++++++++++++++
  SEQUENCE    OID (signedData)
  (2 byte len)

     For a pkcs12 message we have this:

  30 82 08 59 02 01 03 30 82 08 1F 06 09 2A 86 48 86 F7 0D 01 07 01 A0 82
  ----------- ++++++++ ----------- ++++++++++++++++++++++++++++++++
  SEQUENCE    INTEGER  SEQUENCE    OID (data)

    This we need to read at least 22 bytes, we add 2 bytes to cope with
    length headers store with 4 bytes.
  */

  for (count = sizeof buffer; count; count -= n)
    {
      if (ksba_reader_read (reader, buffer+sizeof (buffer)-count, count, &n))
        return KSBA_CT_NONE; /* too short */
    }
  n = sizeof buffer;
  if (ksba_reader_unread (reader, buffer, n))
    return KSBA_CT_NONE; /* oops */

  p = buffer;
  if (_ksba_ber_parse_tl (&p, &n, &ti))
    return KSBA_CT_NONE;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return KSBA_CT_NONE;
  if (_ksba_ber_parse_tl (&p, &n, &ti))
    return KSBA_CT_NONE;
  if ( ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_INTEGER
       && !ti.is_constructed && ti.length == 1 && n && *p == 3)
    {
      maybe_p12 = 1;
      p++;
      n--;
      if (_ksba_ber_parse_tl (&p, &n, &ti))
        return KSBA_CT_NONE;
      if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
             && ti.is_constructed) )
        return KSBA_CT_NONE;
      if (_ksba_ber_parse_tl (&p, &n, &ti))
        return KSBA_CT_NONE;
    }
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OBJECT_ID
         && !ti.is_constructed && ti.length) || ti.length > n)
    return KSBA_CT_NONE;
  oid = ksba_oid_to_str (p, ti.length);
  if (!oid)
    return KSBA_CT_NONE; /* out of core */
  for (i=0; content_handlers[i].oid; i++)
    {
      if (!strcmp (content_handlers[i].oid, oid))
        break;
    }
  ksba_free(oid);
  if (!content_handlers[i].oid)
    return KSBA_CT_NONE; /* unknown */
  if (maybe_p12 && (content_handlers[i].ct == KSBA_CT_DATA
                    || content_handlers[i].ct == KSBA_CT_SIGNED_DATA))
      return KSBA_CT_PKCS12;
  return content_handlers[i].ct;
}



/**
 * ksba_cms_new:
 *
 * Create a new and empty CMS object
 *
 * Return value: A CMS object or an error code.
 **/
gpg_error_t
ksba_cms_new (ksba_cms_t *r_cms)
{
  *r_cms = xtrycalloc (1, sizeof **r_cms);
  if (!*r_cms)
    return gpg_error_from_errno (errno);
  return 0;
}

/* Release a list of value trees. */
static void
release_value_tree (struct value_tree_s *tree)
{
  while (tree)
    {
      struct value_tree_s *tmp = tree->next;
      _ksba_asn_release_nodes (tree->root);
      xfree (tree->image);
      xfree (tree);
      tree = tmp;
    }
}

/**
 * ksba_cms_release:
 * @cms: A CMS object
 *
 * Release a CMS object.
 **/
void
ksba_cms_release (ksba_cms_t cms)
{
  if (!cms)
    return;
  xfree (cms->content.oid);
  while (cms->digest_algos)
    {
      struct oidlist_s *ol = cms->digest_algos->next;
      xfree (cms->digest_algos->oid);
      xfree (cms->digest_algos);
      cms->digest_algos = ol;
    }
  while (cms->cert_list)
    {
      struct certlist_s *cl = cms->cert_list->next;
      ksba_cert_release (cms->cert_list->cert);
      xfree (cms->cert_list->enc_val.algo);
      xfree (cms->cert_list->enc_val.value);
      xfree (cms->cert_list->enc_val.ecdh.e);
      xfree (cms->cert_list->enc_val.ecdh.wrap_algo);
      xfree (cms->cert_list->enc_val.ecdh.encr_algo);
      xfree (cms->cert_list);
      cms->cert_list = cl;
    }
  while (cms->cert_info_list)
    {
      struct certlist_s *cl = cms->cert_info_list->next;
      ksba_cert_release (cms->cert_info_list->cert);
      xfree (cms->cert_info_list->enc_val.algo);
      xfree (cms->cert_info_list->enc_val.value);
      xfree (cms->cert_info_list);
      cms->cert_info_list = cl;
    }
  xfree (cms->inner_cont_oid);
  xfree (cms->encr_algo_oid);
  xfree (cms->encr_algo_sbox_oid);
  xfree (cms->encr_iv);
  xfree (cms->data.digest);
  while (cms->signer_info)
    {
      struct signer_info_s *tmp = cms->signer_info->next;
      _ksba_asn_release_nodes (cms->signer_info->root);
      xfree (cms->signer_info->image);
      xfree (cms->signer_info->cache.digest_algo);
      xfree (cms->signer_info);
      cms->signer_info = tmp;
    }
  release_value_tree (cms->recp_info);
  while (cms->sig_val)
    {
      struct sig_val_s *tmp = cms->sig_val->next;
      xfree (cms->sig_val->algo);
      xfree (cms->sig_val->value);
      xfree (cms->sig_val);
      cms->sig_val = tmp;
    }
  while (cms->capability_list)
    {
      struct oidparmlist_s *tmp = cms->capability_list->next;
      xfree (cms->capability_list->oid);
      xfree (cms->capability_list);
      cms->capability_list = tmp;
    }

  xfree (cms);
}


gpg_error_t
ksba_cms_set_reader_writer (ksba_cms_t cms, ksba_reader_t r, ksba_writer_t w)
{
  if (!cms || !(r || w))
    return gpg_error (GPG_ERR_INV_VALUE);
  if ((r && cms->reader) || (w && cms->writer) )
    return gpg_error (GPG_ERR_CONFLICT); /* already set */

  cms->reader = r;
  cms->writer = w;
  return 0;
}



gpg_error_t
ksba_cms_parse (ksba_cms_t cms, ksba_stop_reason_t *r_stopreason)
{
  gpg_error_t err;
  int i;

  if (!cms || !r_stopreason)
    return gpg_error (GPG_ERR_INV_VALUE);

  *r_stopreason = KSBA_SR_RUNNING;
  if (!cms->stop_reason)
    { /* Initial state: start parsing */
      err = _ksba_cms_parse_content_info (cms);
      if (err)
        return err;
      for (i=0; content_handlers[i].oid; i++)
        {
          if (!strcmp (content_handlers[i].oid, cms->content.oid))
            break;
        }
      if (!content_handlers[i].oid)
        return gpg_error (GPG_ERR_UNKNOWN_CMS_OBJ);
      if (!content_handlers[i].parse_handler)
        return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);
      cms->content.ct      = content_handlers[i].ct;
      cms->content.handler = content_handlers[i].parse_handler;
      cms->stop_reason = KSBA_SR_GOT_CONTENT;
    }
  else if (cms->content.handler)
    {
      err = cms->content.handler (cms);
      if (err)
        return err;
    }
  else
    return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);

  *r_stopreason = cms->stop_reason;
  return 0;
}

gpg_error_t
ksba_cms_build (ksba_cms_t cms, ksba_stop_reason_t *r_stopreason)
{
  gpg_error_t err;

  if (!cms || !r_stopreason)
    return gpg_error (GPG_ERR_INV_VALUE);

  *r_stopreason = KSBA_SR_RUNNING;
  if (!cms->stop_reason)
    { /* Initial state: check that the content handler is known */
      if (!cms->writer)
        return gpg_error (GPG_ERR_MISSING_ACTION);
      if (!cms->content.handler)
        return gpg_error (GPG_ERR_MISSING_ACTION);
      if (!cms->inner_cont_oid)
        return gpg_error (GPG_ERR_MISSING_ACTION);
      cms->stop_reason = KSBA_SR_GOT_CONTENT;
    }
  else if (cms->content.handler)
    {
      err = cms->content.handler (cms);
      if (err)
        return err;
    }
  else
    return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);

  *r_stopreason = cms->stop_reason;
  return 0;
}




/* Return the content type.  A WHAT of 0 returns the real content type
   whereas a 1 returns the inner content type.
*/
ksba_content_type_t
ksba_cms_get_content_type (ksba_cms_t cms, int what)
{
  int i;

  if (!cms)
    return 0;
  if (!what)
    return cms->content.ct;

  if (what == 1 && cms->inner_cont_oid)
    {
      for (i=0; content_handlers[i].oid; i++)
        {
          if (!strcmp (content_handlers[i].oid, cms->inner_cont_oid))
            return content_handlers[i].ct;
        }
    }
  return 0;
}


/* Return the object ID of the current cms.  This is a constant string
   valid as long as the context is valid and no new parse is
   started. */
const char *
ksba_cms_get_content_oid (ksba_cms_t cms, int what)
{
  if (!cms)
    return NULL;
  if (!what)
    return cms->content.oid;
  if (what == 1)
    return cms->inner_cont_oid;
  if (what == 2)
    return cms->encr_algo_oid;
  if (what == 3)
    return cms->encr_algo_sbox_oid;
  return NULL;
}


/* Copy the initialization vector into iv and its len into ivlen.
   The caller should provide a suitable large buffer */
gpg_error_t
ksba_cms_get_content_enc_iv (ksba_cms_t cms, void *iv,
                             size_t maxivlen, size_t *ivlen)
{
  if (!cms || !iv || !ivlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!cms->encr_ivlen)
    return gpg_error (GPG_ERR_NO_DATA);
  if (cms->encr_ivlen > maxivlen)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
  memcpy (iv, cms->encr_iv, cms->encr_ivlen);
  *ivlen = cms->encr_ivlen;
  return 0;
}


/**
 * ksba_cert_get_digest_algo_list:
 * @cert: Initialized certificate object
 * @idx: enumerator
 *
 * Figure out the the digest algorithm used for the signature and
 * return its OID.  Note that the algos returned are just hints on
 * what to hash.
 *
 * Return value: NULL for no more algorithms or a string valid as long
 * as the the cms object is valid.
 **/
const char *
ksba_cms_get_digest_algo_list (ksba_cms_t cms, int idx)
{
  struct oidlist_s *ol;

  if (!cms)
    return NULL;

  for (ol=cms->digest_algos; ol && idx; ol = ol->next, idx-- )
    ;
  if (!ol)
    return NULL;
  return ol->oid;
}


/**
 * ksba_cms_get_issuer_serial:
 * @cms: CMS object
 * @idx: index number
 * @r_issuer: returns the issuer
 * @r_serial: returns the serial number
 *
 * This functions returns the issuer and serial number either from the
 * sid or the rid elements of a CMS object.
 *
 * Return value: 0 on success or an error code.  An error code of -1
 * is returned to indicate that there is no issuer with that idx,
 * GPG_ERR_No_Data is returned to indicate that there is no issuer at
 * all.
 **/
gpg_error_t
ksba_cms_get_issuer_serial (ksba_cms_t cms, int idx,
                            char **r_issuer, ksba_sexp_t *r_serial)
{
  gpg_error_t err;
  const char *issuer_path, *serial_path;
  AsnNode root;
  const unsigned char *image;
  AsnNode n;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  if (cms->signer_info)
    {
      struct signer_info_s *si;

      for (si=cms->signer_info; si && idx; si = si->next, idx-- )
        ;
      if (!si)
        return -1;

      root = si->root;
      image = si->image;
    }
  else if (cms->recp_info)
    {
      struct value_tree_s *tmp;

      for (tmp=cms->recp_info; tmp && idx; tmp=tmp->next, idx-- )
        ;
      if (!tmp)
        return -1;
      root = tmp->root;
      image = tmp->image;
    }
  else
    return gpg_error (GPG_ERR_NO_DATA);


  if (cms->signer_info)
    {
      issuer_path = "SignerInfo.sid.issuerAndSerialNumber.issuer";
      serial_path = "SignerInfo.sid.issuerAndSerialNumber.serialNumber";
    }
  else if (cms->recp_info)
    {
      /* Find the choice to use.  */
      n = _ksba_asn_find_node (root, "RecipientInfo.+");
      if (!n || !n->name)
        return gpg_error (GPG_ERR_NO_VALUE);

      if (!strcmp (n->name, "ktri"))
        {
          issuer_path = "ktri.rid.issuerAndSerialNumber.issuer";
          serial_path = "ktri.rid.issuerAndSerialNumber.serialNumber";
        }
      else if (!strcmp (n->name, "kari"))
        {
          issuer_path = ("kari..recipientEncryptedKeys"
                         "..rid.issuerAndSerialNumber.issuer");
          serial_path = ("kari..recipientEncryptedKeys"
                         "..rid.issuerAndSerialNumber.serialNumber");
        }
      else if (!strcmp (n->name, "kekri"))
        return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);
      else
        return gpg_error (GPG_ERR_INV_CMS_OBJ);
      root = n;
    }

  if (r_issuer)
    {
      n = _ksba_asn_find_node (root, issuer_path);
      if (!n || !n->down)
        return gpg_error (GPG_ERR_NO_VALUE);
      n = n->down; /* dereference the choice node */

      if (n->off == -1)
        {
/*            fputs ("get_issuer problem at node:\n", stderr); */
/*            _ksba_asn_node_dump_all (n, stderr); */
          return gpg_error (GPG_ERR_GENERAL);
        }
      err = _ksba_dn_to_str (image, n, r_issuer);
      if (err)
        return err;
    }

  if (r_serial)
    {
      char numbuf[22];
      int numbuflen;
      unsigned char *p;

      /* fixme: we do not release the r_issuer stuff on error */
      n = _ksba_asn_find_node (root, serial_path);
      if (!n)
        return gpg_error (GPG_ERR_NO_VALUE);

      if (n->off == -1)
        {
/*            fputs ("get_serial problem at node:\n", stderr); */
/*            _ksba_asn_node_dump_all (n, stderr); */
          return gpg_error (GPG_ERR_GENERAL);
        }

      sprintf (numbuf,"(%u:", (unsigned int)n->len);
      numbuflen = strlen (numbuf);
      p = xtrymalloc (numbuflen + n->len + 2);
      if (!p)
        return gpg_error (GPG_ERR_ENOMEM);
      strcpy (p, numbuf);
      memcpy (p+numbuflen, image + n->off + n->nhdr, n->len);
      p[numbuflen + n->len] = ')';
      p[numbuflen + n->len + 1] = 0;
      *r_serial = p;
    }

  return 0;
}



/**
 * ksba_cms_get_digest_algo:
 * @cms: CMS object
 * @idx: index of signer
 *
 * Figure out the the digest algorithm used by the signer @idx return
 * its OID.  This is the algorithm acually used to calculate the
 * signature.
 *
 * Return value: NULL for no such signer or a constn string valid as
 * long as the CMS object lives.
 **/
const char *
ksba_cms_get_digest_algo (ksba_cms_t cms, int idx)
{
  AsnNode n;
  char *algo;
  struct signer_info_s *si;

  if (!cms)
    return NULL;
  if (!cms->signer_info)
    return NULL;
  if (idx < 0)
    return NULL;

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return NULL;

  if (si->cache.digest_algo)
    return si->cache.digest_algo;

  n = _ksba_asn_find_node (si->root, "SignerInfo.digestAlgorithm.algorithm");
  algo = _ksba_oid_node_to_str (si->image, n);
  if (algo)
    {
      si->cache.digest_algo = algo;
    }
  return algo;
}


/**
 * ksba_cms_get_cert:
 * @cms: CMS object
 * @idx: enumerator
 *
 * Get the certificate out of a CMS.  The caller should use this in a
 * loop to get all certificates.  The returned certificate is a
 * shallow copy of the original one; the caller must still use
 * ksba_cert_release() to free it.
 *
 * Return value: A Certificate object or NULL for end of list or error
 **/
ksba_cert_t
ksba_cms_get_cert (ksba_cms_t cms, int idx)
{
  struct certlist_s *cl;

  if (!cms || idx < 0)
    return NULL;

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return NULL;
  ksba_cert_ref (cl->cert);
  return cl->cert;
}


/*
   Return the extension attribute messageDigest
*/
gpg_error_t
ksba_cms_get_message_digest (ksba_cms_t cms, int idx,
                             char **r_digest, size_t *r_digest_len)
{
  AsnNode nsiginfo, n;
  struct signer_info_s *si;

  if (!cms || !r_digest || !r_digest_len)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!cms->signer_info)
    return gpg_error (GPG_ERR_NO_DATA);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return -1;


  *r_digest = NULL;
  *r_digest_len = 0;
  nsiginfo = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
  if (!nsiginfo)
    return gpg_error (GPG_ERR_BUG);

  n = _ksba_asn_find_type_value (si->image, nsiginfo, 0,
                                 oid_messageDigest, DIM(oid_messageDigest));
  if (!n)
    return 0; /* this is okay, because the element is optional */

  /* check that there is only one */
  if (_ksba_asn_find_type_value (si->image, nsiginfo, 1,
                                 oid_messageDigest, DIM(oid_messageDigest)))
    return gpg_error (GPG_ERR_DUP_VALUE);

  /* the value is is a SET OF OCTECT STRING but the set must have
     excactly one OCTECT STRING.  (rfc2630 11.2) */
  if ( !(n->type == TYPE_SET_OF && n->down
         && n->down->type == TYPE_OCTET_STRING && !n->down->right))
    return gpg_error (GPG_ERR_INV_CMS_OBJ);
  n = n->down;
  if (n->off == -1)
    return gpg_error (GPG_ERR_BUG);

  *r_digest_len = n->len;
  *r_digest = xtrymalloc (n->len);
  if (!*r_digest)
    return gpg_error (GPG_ERR_ENOMEM);
  memcpy (*r_digest, si->image + n->off + n->nhdr, n->len);
  return 0;
}


/* Return the extension attribute signing time, which may be empty for no
   signing time available. */
gpg_error_t
ksba_cms_get_signing_time (ksba_cms_t cms, int idx, ksba_isotime_t r_sigtime)
{
  AsnNode nsiginfo, n;
  struct signer_info_s *si;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  *r_sigtime = 0;
  if (!cms->signer_info)
    return gpg_error (GPG_ERR_NO_DATA);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return -1;

  *r_sigtime = 0;
  nsiginfo = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
  if (!nsiginfo)
    return 0; /* This is okay because signedAttribs are optional. */

  n = _ksba_asn_find_type_value (si->image, nsiginfo, 0,
                                 oid_signingTime, DIM(oid_signingTime));
  if (!n)
    return 0; /* This is okay because signing time is optional. */

  /* check that there is only one */
  if (_ksba_asn_find_type_value (si->image, nsiginfo, 1,
                                 oid_signingTime, DIM(oid_signingTime)))
    return gpg_error (GPG_ERR_DUP_VALUE);

  /* the value is is a SET OF CHOICE but the set must have
     excactly one CHOICE of generalized or utctime.  (rfc2630 11.3) */
  if ( !(n->type == TYPE_SET_OF && n->down
         && (n->down->type == TYPE_GENERALIZED_TIME
             || n->down->type == TYPE_UTC_TIME)
         && !n->down->right))
    return gpg_error (GPG_ERR_INV_CMS_OBJ);
  n = n->down;
  if (n->off == -1)
    return gpg_error (GPG_ERR_BUG);

  return _ksba_asntime_to_iso (si->image + n->off + n->nhdr, n->len,
                               n->type == TYPE_UTC_TIME, r_sigtime);
}


/* Return a list of OIDs stored as signed attributes for the signature
   number IDX.  All the values (OIDs) for the the requested OID REQOID
   are returned delimited by a linefeed.  Caller must free that
   list. -1 is returned when IDX is larger than the number of
   signatures, GPG_ERR_No_Data is returned when there is no such
   attribute for the given signer. */
gpg_error_t
ksba_cms_get_sigattr_oids (ksba_cms_t cms, int idx,
                           const char *reqoid, char **r_value)
{
  gpg_error_t err;
  AsnNode nsiginfo, n;
  struct signer_info_s *si;
  unsigned char *reqoidbuf;
  size_t reqoidlen;
  char *retstr = NULL;
  int i;

  if (!cms || !r_value)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!cms->signer_info)
    return gpg_error (GPG_ERR_NO_DATA);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);
  *r_value = NULL;

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return -1; /* no more signers */

  nsiginfo = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
  if (!nsiginfo)
    return -1; /* this is okay, because signedAttribs are optional */

  err = ksba_oid_from_str (reqoid, &reqoidbuf, &reqoidlen);
  if(err)
    return err;

  for (i=0; (n = _ksba_asn_find_type_value (si->image, nsiginfo,
                                            i, reqoidbuf, reqoidlen)); i++)
    {
      char *line, *p;

      /* the value is is a SET OF OBJECT ID but the set must have
         excactly one OBJECT ID.  (rfc2630 11.1) */
      if ( !(n->type == TYPE_SET_OF && n->down
             && n->down->type == TYPE_OBJECT_ID && !n->down->right))
        {
          xfree (reqoidbuf);
          xfree (retstr);
          return gpg_error (GPG_ERR_INV_CMS_OBJ);
        }
      n = n->down;
      if (n->off == -1)
        {
          xfree (reqoidbuf);
          xfree (retstr);
          return gpg_error (GPG_ERR_BUG);
        }

      p = _ksba_oid_node_to_str (si->image, n);
      if (!p)
        {
          xfree (reqoidbuf);
          xfree (retstr);
          return gpg_error (GPG_ERR_INV_CMS_OBJ);
        }

      if (!retstr)
        line = retstr = xtrymalloc (strlen (p) + 2);
      else
        {
          char *tmp = xtryrealloc (retstr,
                                   strlen (retstr) + 1 + strlen (p) + 2);
          if (!tmp)
            line = NULL;
          else
            {
              retstr = tmp;
              line = stpcpy (retstr + strlen (retstr), "\n");
            }
        }
      if (!line)
        {
          xfree (reqoidbuf);
          xfree (retstr);
          xfree (p);
          return gpg_error (GPG_ERR_ENOMEM);
        }
      strcpy (line, p);
      xfree (p);
    }
  xfree (reqoidbuf);
  if (!n && !i)
    return -1; /* no such attribute */
  *r_value = retstr;
  return 0;
}


/**
 * ksba_cms_get_sig_val:
 * @cms: CMS object
 * @idx: index of signer
 *
 * Return the actual signature of signer @idx in a format suitable to
 * be used as input to Libgcrypt's verification function.  The caller
 * must free the returned string.
 *
 * Return value: NULL or a string with a S-Exp.
 **/
ksba_sexp_t
ksba_cms_get_sig_val (ksba_cms_t cms, int idx)
{
  AsnNode n, n2;
  gpg_error_t err;
  ksba_sexp_t string;
  struct signer_info_s *si;

  if (!cms)
    return NULL;
  if (!cms->signer_info)
    return NULL;
  if (idx < 0)
    return NULL;

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return NULL;

  n = _ksba_asn_find_node (si->root, "SignerInfo.signatureAlgorithm");
  if (!n)
      return NULL;
  if (n->off == -1)
    {
/*        fputs ("ksba_cms_get_sig_val problem at node:\n", stderr); */
/*        _ksba_asn_node_dump_all (n, stderr); */
      return NULL;
    }

  n2 = n->right; /* point to the actual value */
  err = _ksba_sigval_to_sexp (si->image + n->off,
                              n->nhdr + n->len
                              + ((!n2||n2->off == -1)? 0:(n2->nhdr+n2->len)),
                              &string);
  if (err)
      return NULL;

  return string;
}


/* Helper to dump a S-expression. */
#if 0
static void
dbg_print_sexp (ksba_const_sexp_t p)
{
  int level = 0;

  if (!p)
    fputs ("[none]", stdout);
  else
    {
      for (;;)
        {
          if (*p == '(')
            {
              putchar (*p);
              p++;
              level++;
            }
          else if (*p == ')')
            {
              putchar (*p);
              p++;
              if (--level <= 0 )
                {
                  putchar ('\n');
                  return;
                }
            }
          else if (!digitp (p))
            {
              fputs ("[invalid s-exp]\n", stdout);
              return;
            }
          else
            {
              const unsigned char *s;
              char *endp;
              unsigned long len, n;

              len = strtoul (p, &endp, 10);
              p = endp;
              if (*p != ':')
                {
                  fputs ("[invalid s-exp]\n", stdout);
                  return;
                }
              p++;
              for (s=p,n=0; n < len; n++, s++)
                if ( !((*s >= 'a' && *s <= 'z')
                       || (*s >= 'A' && *s <= 'Z')
                       || (*s >= '0' && *s <= '9')
                       || *s == '-' || *s == '.'))
                  break;
              if (n < len)
                {
                  putchar('#');
                  for (n=0; n < len; n++, p++)
                    printf ("%02X", *p);
                  putchar('#');
                }
              else
                {
                  for (n=0; n < len; n++, p++)
                    putchar (*p);
                }
            }
        }
    }
  putchar ('\n');
}
#endif /* 0 */



/**
 * ksba_cms_get_enc_val:
 * @cms: CMS object
 * @idx: index of recipient info
 *
 * Return the encrypted value (the session key) of recipient @idx in a
 * format suitable to be used as input to Libgcrypt's decryption
 * function.  The caller must free the returned string.
 *
 * Return value: NULL or a string with a S-Exp.
 **/
ksba_sexp_t
ksba_cms_get_enc_val (ksba_cms_t cms, int idx)
{
  AsnNode root, n, n2;
  gpg_error_t err;
  ksba_sexp_t string;
  struct value_tree_s *vt;
  char *keyencralgo = NULL; /* Key encryption algo.  */
  char *parm = NULL;        /* Helper to get the parms of kencralgo.  */
  size_t parmlen;
  char *keywrapalgo = NULL; /* Key wrap algo.  */
  struct tag_info ti;
  const unsigned char *der;
  size_t derlen;

  if (!cms)
    return NULL;
  if (!cms->recp_info)
    return NULL;
  if (idx < 0)
    return NULL;

  for (vt=cms->recp_info; vt && idx; vt=vt->next, idx--)
    ;
  if (!vt)
    return NULL; /* No value at this IDX */

  /* Find the choice to use.  */
  root = _ksba_asn_find_node (vt->root, "RecipientInfo.+");
  if (!root || !root->name)
    return NULL;

  if (!strcmp (root->name, "ktri"))
    {
      n = _ksba_asn_find_node (root, "ktri.keyEncryptionAlgorithm");
      if (!n || n->off == -1)
        return NULL;
      n2 = n->right; /* point to the actual value */
      err = _ksba_encval_to_sexp
        (vt->image + n->off,
         n->nhdr + n->len + ((!n2||n2->off == -1)? 0:(n2->nhdr+n2->len)),
         &string);
    }
  else if (!strcmp (root->name, "kari"))
    {
      /* _ksba_asn_node_dump_all (root, stderr); */

      /* Get the encrypted key.  Result is in (DER,DERLEN)  */
      n = _ksba_asn_find_node (root, ("kari..recipientEncryptedKeys"
                                      "..encryptedKey"));
      if (!n || n->off == -1)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }

      der = vt->image + n->off;
      derlen = n->nhdr + n->len;
      err = parse_octet_string (&der, &derlen, &ti);
      if (err)
        goto leave;
      derlen = ti.length;
      /* gpgrt_log_printhex (der, derlen, "%s: encryptedKey", __func__); */

      /* Get the KEK algos.  */
      n = _ksba_asn_find_node (root, "kari..keyEncryptionAlgorithm");
      if (!n || n->off == -1)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      err = _ksba_parse_algorithm_identifier2 (vt->image + n->off,
                                               n->nhdr + n->len, NULL,
                                               &keyencralgo, &parm, &parmlen);
      if (err)
        goto leave;
      if (!parm)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      err = _ksba_parse_algorithm_identifier (parm, parmlen,NULL, &keywrapalgo);
      if (err)
        goto leave;

      /* gpgrt_log_debug ("%s: keyencralgo='%s'\n", __func__, keyencralgo); */
      /* gpgrt_log_debug ("%s: keywrapalgo='%s'\n", __func__, keywrapalgo); */

      /* Get the ephemeral public key.  */
      n = _ksba_asn_find_node (root, "kari..originator..originatorKey");
      if (!n || n->off == -1)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      err = _ksba_encval_kari_to_sexp (vt->image + n->off, n->nhdr + n->len,
                                       keyencralgo, keywrapalgo, der, derlen,
                                       &string);
      if (err)
        goto leave;

      /* gpgrt_log_debug ("%s: encryptedKey:\n", __func__); */
      /* dbg_print_sexp (string); */
    }
  else if (!strcmp (n->name, "kekri"))
    return NULL; /*GPG_ERR_UNSUPPORTED_CMS_OBJ*/
  else
    return NULL; /*GPG_ERR_INV_CMS_OBJ*/

 leave:
  xfree (keyencralgo);
  xfree (keywrapalgo);
  xfree (parm);
  if (err)
    {
      /* gpgrt_log_debug ("%s: error: %s\n", __func__, gpg_strerror (err)); */
      return NULL;
    }

  return string;
}





/* Provide a hash function so that we are able to hash the data */
void
ksba_cms_set_hash_function (ksba_cms_t cms,
                            void (*hash_fnc)(void *, const void *, size_t),
                            void *hash_fnc_arg)
{
  if (cms)
    {
      cms->hash_fnc = hash_fnc;
      cms->hash_fnc_arg = hash_fnc_arg;
    }
}


/* hash the signed attributes of the given signer */
gpg_error_t
ksba_cms_hash_signed_attrs (ksba_cms_t cms, int idx)
{
  AsnNode n;
  struct signer_info_s *si;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!cms->hash_fnc)
    return gpg_error (GPG_ERR_MISSING_ACTION);
  if (idx < 0)
    return -1;

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return -1;

  n = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
  if (!n || n->off == -1)
    return gpg_error (GPG_ERR_NO_VALUE);

  /* We don't hash the implicit tag [0] but a SET tag */
  cms->hash_fnc (cms->hash_fnc_arg, "\x31", 1);
  cms->hash_fnc (cms->hash_fnc_arg,
                 si->image + n->off + 1, n->nhdr + n->len - 1);

  return 0;
}


/*
  Code to create CMS structures
*/


/**
 * ksba_cms_set_content_type:
 * @cms: A CMS object
 * @what: 0 for content type, 1 for inner content type
 * @type: Type constant
 *
 * Set the content type used for build operations.  This should be the
 * first operation before starting to create a CMS message.
 *
 * Return value: 0 on success or an error code
 **/
gpg_error_t
ksba_cms_set_content_type (ksba_cms_t cms, int what, ksba_content_type_t type)
{
  int i;
  char *oid;

  if (!cms || what < 0 || what > 1 )
    return gpg_error (GPG_ERR_INV_VALUE);

  for (i=0; content_handlers[i].oid; i++)
    {
      if (content_handlers[i].ct == type)
        break;
    }
  if (!content_handlers[i].oid)
    return gpg_error (GPG_ERR_UNKNOWN_CMS_OBJ);
  if (!content_handlers[i].build_handler)
    return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);
  oid = xtrystrdup (content_handlers[i].oid);
  if (!oid)
    return gpg_error (GPG_ERR_ENOMEM);

  if (!what)
    {
      cms->content.oid     = oid;
      cms->content.ct      = content_handlers[i].ct;
      cms->content.handler = content_handlers[i].build_handler;
    }
  else
    {
      cms->inner_cont_oid = oid;
    }

  return 0;
}


/**
 * ksba_cms_add_digest_algo:
 * @cms:  A CMS object
 * @oid: A stringified object OID describing the hash algorithm
 *
 * Set the algorithm to be used for creating the hash. Note, that we
 * currently can't do a per-signer hash.
 *
 * Return value: 0 on success or an error code
 **/
gpg_error_t
ksba_cms_add_digest_algo (ksba_cms_t cms, const char *oid)
{
  struct oidlist_s *ol;

  if (!cms || !oid)
    return gpg_error (GPG_ERR_INV_VALUE);

  ol = xtrymalloc (sizeof *ol);
  if (!ol)
    return gpg_error (GPG_ERR_ENOMEM);

  ol->oid = xtrystrdup (oid);
  if (!ol->oid)
    {
      xfree (ol);
      return gpg_error (GPG_ERR_ENOMEM);
    }
  ol->next = cms->digest_algos;
  cms->digest_algos = ol;
  return 0;
}


/**
 * ksba_cms_add_signer:
 * @cms: A CMS object
 * @cert: A certificate used to describe the signer.
 *
 * This functions starts assembly of a new signed data content or adds
 * another signer to the list of signers.
 *
 * Return value: 0 on success or an error code.
 **/
gpg_error_t
ksba_cms_add_signer (ksba_cms_t cms, ksba_cert_t cert)
{
  struct certlist_s *cl, *cl2;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);

  cl = xtrycalloc (1,sizeof *cl);
  if (!cl)
      return gpg_error (GPG_ERR_ENOMEM);

  ksba_cert_ref (cert);
  cl->cert = cert;
  if (!cms->cert_list)
    cms->cert_list = cl;
  else
    {
      for (cl2=cms->cert_list; cl2->next; cl2 = cl2->next)
        ;
      cl2->next = cl;
    }
  return 0;
}

/**
 * ksba_cms_add_cert:
 * @cms: A CMS object
 * @cert: A certificate to be send along with the signed data.
 *
 * This functions adds a certificate to the list of certificates send
 * along with the signed data.  Using this is optional but it is very
 * common to include at least the certificate of the signer it self.
 *
 * Return value: 0 on success or an error code.
 **/
gpg_error_t
ksba_cms_add_cert (ksba_cms_t cms, ksba_cert_t cert)
{
  struct certlist_s *cl;

  if (!cms || !cert)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* first check whether this is a duplicate. */
  for (cl = cms->cert_info_list; cl; cl = cl->next)
    {
      if (!_ksba_cert_cmp (cert, cl->cert))
        return 0; /* duplicate */
    }

  /* Okay, add it. */
  cl = xtrycalloc (1,sizeof *cl);
  if (!cl)
      return gpg_error (GPG_ERR_ENOMEM);

  ksba_cert_ref (cert);
  cl->cert = cert;
  cl->next = cms->cert_info_list;
  cms->cert_info_list = cl;
  return 0;
}


/* Add an S/MIME capability as an extended attribute to the message.
   This function is to be called for each capability in turn. The
   first capability added will receive the highest priority.  CMS is
   the context, OID the object identifier of the capability and if DER
   is not NULL it is used as the DER-encoded parameters of the
   capability; the length of that DER object is given in DERLEN.
   DERLEN should be 0 if DER is NULL.

   The function returns 0 on success or an error code.
*/
gpg_error_t
ksba_cms_add_smime_capability (ksba_cms_t cms, const char *oid,
                               const unsigned char *der, size_t derlen)
{
  gpg_error_t err;
  struct oidparmlist_s *opl, *opl2;

  if (!cms || !oid)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!der)
    derlen = 0;

  opl = xtrymalloc (sizeof *opl + derlen - 1);
  if (!opl)
    return gpg_error_from_errno (errno);
  opl->next = NULL;
  opl->oid = xtrystrdup (oid);
  if (!opl->oid)
    {
      err = gpg_error_from_errno (errno);
      xfree (opl);
      return err;
    }
  opl->parmlen = derlen;
  if (der)
    memcpy (opl->parm, der, derlen);

  /* Append it to maintain the desired order. */
  if (!cms->capability_list)
    cms->capability_list = opl;
  else
    {
      for (opl2=cms->capability_list; opl2->next; opl2 = opl2->next)
        ;
      opl2->next = opl;
    }

  return 0;
}



/**
 * ksba_cms_set_message_digest:
 * @cms: A CMS object
 * @idx: The index of the signer
 * @digest: a message digest
 * @digest_len: the length of the message digest
 *
 * Set a message digest into the signedAttributes of the signer with
 * the index IDX.  The index of a signer is determined by the sequence
 * of ksba_cms_add_signer() calls; the first signer has the index 0.
 * This function is to be used when the hash value of the data has
 * been calculated and before the create function requests the sign
 * operation.
 *
 * Return value: 0 on success or an error code
 **/
gpg_error_t
ksba_cms_set_message_digest (ksba_cms_t cms, int idx,
                             const unsigned char *digest, size_t digest_len)
{
  struct certlist_s *cl;

  if (!cms || !digest)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!digest_len || digest_len > DIM(cl->msg_digest))
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return gpg_error (GPG_ERR_INV_INDEX); /* no certificate to store it */
  cl->msg_digest_len = digest_len;
  memcpy (cl->msg_digest, digest, digest_len);
  return 0;
}

/**
 * ksba_cms_set_signing_time:
 * @cms: A CMS object
 * @idx: The index of the signer
 * @sigtime: a time or an empty value to use the current time
 *
 * Set a signing time into the signedAttributes of the signer with
 * the index IDX.  The index of a signer is determined by the sequence
 * of ksba_cms_add_signer() calls; the first signer has the index 0.
 *
 * Return value: 0 on success or an error code
 **/
gpg_error_t
ksba_cms_set_signing_time (ksba_cms_t cms, int idx, const ksba_isotime_t sigtime)
{
  struct certlist_s *cl;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return gpg_error (GPG_ERR_INV_INDEX); /* no certificate to store it */

  /* Fixme: We might want to check the validity of the passed time
     string. */
  if (!*sigtime)
    _ksba_current_time (cl->signing_time);
  else
    _ksba_copy_time (cl->signing_time, sigtime);
  return 0;
}

typedef struct {
  const char *name;
  const unsigned char *value;
  size_t len;
} parsed_values_t;

static gpg_error_t
read_values (const unsigned char **s, const char * const *params,
			 int count, parsed_values_t *values)
{
  unsigned long n;
  gpg_error_t err = 0;

  while (**s == '(')
    {
	  (*s)++;
	  if (!(n = snext (s)))
		{
		  err = gpg_error (GPG_ERR_INV_SEXP);
		  goto exit;
		}

	  int validx = 0;

	  if (0 == count)
		(*s) += n; /* ignore the name of the parameter */
	  else
		{
		  while (validx < count && !smatch (s, n, params[validx]))
			validx++;
		}

	  if (!digitp(*s) || !(n = snext (s)))
		{
		  err = gpg_error (GPG_ERR_INV_SEXP);
		  goto exit;
		}

      if (!count || validx < count)
        {
          if (count)
            values[validx].name = params[validx];
          values[validx].value = *s;
          values[validx].len = n;
        }

	  (*s) += n;

	  if ( **s != ')')
		return  gpg_error (GPG_ERR_INV_SEXP);
	  (*s)++;
	}

 exit:

  return err;
}

static gpg_error_t
pack_values (const parsed_values_t *values, int count,
			 unsigned char **value, size_t *valuelen)
{
  int validx;
  gpg_error_t err = 0;

  *valuelen = 0;
  for (validx = 0; validx < (count ? count : 1); validx++)
	*valuelen += values[validx].len;

  *value = xtrymalloc (*valuelen);
  if (!*value)
	return gpg_error (GPG_ERR_ENOMEM);

  for (validx = 0; validx < (count ? count : 1); validx++)
	memcpy (*value + (validx ? values[validx-1].len : 0),
			values[validx].value, values[validx].len);

  return err;
}

static gpg_error_t
ecdsa_values (const parsed_values_t *values, int count,
              unsigned char **value, size_t *valuelen)
{
  ksba_der_t dbld = _ksba_der_builder_new (0);
  if (!dbld)
    {
      err = gpg_error_from_syserror ();
      return err;
    }

  const parsed_values_t *r = find_value ("r", values, count);
  const parsed_values_t *s = find_value ("s", values, count);

  if (r && s)
    {
      _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
      _ksba_der_add_int (dbld, r->value, r->len, 1);
      _ksba_der_add_int (dbld, s->value, s->len, 1);
      _ksba_der_add_end (dbld);

      err = _ksba_der_builder_get (dbld, value, valuelen);
    }
  else
    err = gpg_error (GPG_ERR_UNKNOWN_SEXP);

  _ksba_der_release (dbld);
  return err;
}

static const char *
curve_oid_to_key_algo (const char *curve, size_t curve_len,
                       const char *digest, size_t digest_len)
{
  if (curve)
    {
          // GOST2001-CryptoPro-A,B,C
      if ((curve_len > 15 && 0 == strncmp (curve, "1.2.643.2.2.35.", 15)) ||
          (curve_len > 15 && 0 == strncmp (curve, "1.2.643.2.2.36.", 15)))
        {
          if (digest && 17 == digest_len &&
              0 == strncmp (digest, "1.2.643.7.1.1.2.2", 17))
            return "1.2.643.7.1.1.1.1";
          else
            return "1.2.643.2.2.19";
        }

          // GOST2012-256-A,B,C,D
      if (curve_len > 18 && 0 == strncmp (curve, "1.2.643.7.1.2.1.1.", 18))
        return "1.2.643.7.1.1.1.1";

          // GOST2012-512-A,B
      if (curve_len > 18 && 0 == strncmp (curve, "1.2.643.7.1.2.1.2.", 18))
        return "1.2.643.7.1.1.1.2";
    }

  return NULL;
}

static const char *
key_algo_to_digest_algo (const char *value, size_t len)
{
  if (value)
    {
      /* GOST */
      if (!strcmp (value, "1.2.643.2.2.19"))
        return "1.2.643.2.2.30.1";
      else if (!strcmp (value, "1.2.643.7.1.1.1.1"))
        return "1.2.643.7.1.1.2.2";
      else if (!strcmp (value, "1.2.643.7.1.1.1.2"))
        return "1.2.643.7.1.1.2.3";
    }

  return NULL;
}

static const char *
digest_algo_to_key_algo (const char *value, size_t len)
{
  if (value)
    {
      /* GOST */
      if (!strcmp (value, "1.2.643.2.2.9") ||
          !strcmp (value, "1.2.643.2.2.30.1"))
        return "1.2.643.2.2.19";
      else if (!strcmp (value, "1.2.643.7.1.1.2.2"))
        return "1.2.643.7.1.1.1.1";
      else if (!strcmp (value, "1.2.643.7.1.1.2.3"))
        return "1.2.643.7.1.1.1.2";

      /* ECDSA */
      if (!strcmp (value, "2.16.840.1.101.3.4.2.1"))
        return "1.2.840.10045.4.3.2";  /* ecdsa-with-SHA256 */
      else if (!strcmp (value, "2.16.840.1.101.3.4.2.2"))
        return "1.2.840.10045.4.3.3";  /* ecdsa-with-SHA384 */
      else if (!strcmp (value, "2.16.840.1.101.3.4.2.3"))
        return "1.2.840.10045.4.3.4";  /* ecdsa-with-SHA512 */
    }

  return NULL;
}

/* Set the signature value as a canonical encoded s-expression.
 *
 * r_sig  = (sig-val
 *	      (<algo>
 *		(<param_name1> <mpi>)
 *		...
 *		(<param_namen> <mpi>)
 *	      ))
 *
 * <algo> must be given as a stringified OID or the special string
 * "rsa".  For ECC <algo> must either be "ecdsa", "gost" or the OID
 * matching the used hash algorithm; the expected parameters are "r"
 * and "s".
 *
 * Note that IDX is only used for consistency checks.
 */
gpg_error_t
ksba_cms_set_sig_val (ksba_cms_t cms, int idx, ksba_const_sexp_t sigval)
{
  unsigned long n;
  struct sig_val_s *sv, **sv_tail;
  const unsigned char *s;
  int i;
  gpg_error_t err = 0;

  enum {
        sUNKNOWN,
        sRSA,
        sECDSA,
        sGOST
  } sig_type = sUNKNOWN;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX); /* only one signer for now */

  /* log_sexp ("sigval:", sigval); */
  s = sigval;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;

  for (i=0, sv_tail=&cms->sig_val; *sv_tail; sv_tail=&(*sv_tail)->next, i++)
    ;
  if (i != idx)
    return gpg_error (GPG_ERR_INV_INDEX);

  if (!(n = snext (&s)))
    return gpg_error (GPG_ERR_INV_SEXP);
  if (!smatch (&s, 7, "sig-val"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if (*s != '(')
    return gpg_error (digitp (s)? GPG_ERR_UNKNOWN_SEXP : GPG_ERR_INV_SEXP);
  s++;

  /* Break out the parameters. */
  if (!(n = snext (&s)))
    return gpg_error (GPG_ERR_INV_SEXP);

  sv = xtrycalloc (1, sizeof *sv);
  if (!sv)
    return gpg_error (GPG_ERR_ENOMEM);

  parsed_values_t values[5];
  memset (values, 0, sizeof (values));

  sv->algo = NULL;

  if (smatch (&s, n, "rsa"))
    {
      err = read_values (&s, NULL, 0, values);
      if (err)
        return err;
      sv->algo = xtrystrdup ("1.2.840.113549.1.1.1");
      if (!sv->algo)
        {
          err = gpg_error_from_syserror ();
          goto exit;
        }
      sig_type = sRSA;
    }
  else if (smatch (&s, n, "ecdsa"))
    sig_type = sECDSA;
  else if (smatch (&s, n, "gost"))
    sig_type = sGOST;
  else
    {
      sv->algo = xtrymalloc (n+1);
      if (!sv->algo)
        {
          err = gpg_error_from_syserror ();
          goto exit;
        }
      memcpy (sv->algo, s, n);
      sv->algo[n] = 0;
      s += n;
    }

  if (sv->algo)
    {
      if (!strcmp (sv->algo, "1.2.840.113549.1.1.1"))
        sig_type = sRSA;
      else if (
               /* ecdsa-with-SHA256 */
               !strcmp (sv->algo, "1.2.840.10045.4.3.2")
               /* ecdsa-with-SHA384 */
               || !strcmp (sv->algo, "1.2.840.10045.4.3.3")
               /* ecdsa-with-SHA512 */
               || !strcmp (sv->algo, "1.2.840.10045.4.3.4")
              )
        sig_type = sECDSA;
      else if (
               /* GOST 2001 */ // FIXME: should be sig. algo OIDs!
               !strcmp (sv->algo, "1.2.643.2.2.19")
               /* GOST 2012-256 */
               || !strncmp (sv->algo, "1.2.643.7.1.1.1.1")
               /* GOST 2012-512 */
               || !strncmp (sv->algo, "1.2.643.7.1.1.1.2")
              )
        sig_type = sGOST;
    }

  switch (sig_type)
    {
    case sRSA:
      err = pack_values (values, 0, &sv->value, &sv->valuelen);
      break;
    case sECDSA:
    case sGOST:
      {
        const char * const ec_params[] = { "s", "r", "algo", "curve", "digest" };
        err = read_values (&s, ec_params, 5, values);
        if (err)
          return err;

        if (!sv->algo)
          {
            if (!values[2].value)
              {
                const char *algo_oid = NULL;
                if (!values[4].value || !values[4].len)
                  {
                    values[4].value = ksba_cms_get_digest_algo_list (cms, idx);
                    values[4].len = strlen (values[4].value);
                  }
                if (values[3].value && values[3].len)
                  algo_oid = curve_oid_to_key_algo (values[3].value, values[3].len,
                                                    values[4].value, values[4].len);
                else
                  algo_oid = digest_algo_to_key_algo (values[4].value, values[4].len);

                if (!algo_oid)
                  {
                    err = gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
                    goto exit;
                  }
                sv->algo = xtrystrdup (algo_oid);
                if (!sv->algo)
                  {
                    err = gpg_error_from_syserror ();
                    goto exit;
                  }
              }
            else
              {
                sv->algo = xtrymalloc (values[2].len + 1);
                if (!sv->algo)
                  {
                    err = gpg_error_from_syserror ();
                    goto exit;
                  }
                memcpy (sv->algo, values[2].value, values[2].len);
                sv->algo[values[2].len] = '\0';
              }
          }

        if (sig_type == sGOST)
          err = pack_values (values, 2 /* s, r */, &sv->value,
                             &sv->valuelen);
        else
          /* ECDSA */
          err = ecdsa_values (values, 5, &sv->value, &sv->valuelen);
      }
      break;
    default:
      err = gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
    }

  *sv_tail = sv;

 exit:
  if (err)
	{
	  xfree (sv->value);
      xfree (sv->algo);
      xfree (sv);
	}

  return err;
}


/* Set the content encryption algorithm to OID and optionally set the
   initialization vector to IV */
gpg_error_t
ksba_cms_set_content_enc_algo (ksba_cms_t cms,
                               const char *oid,
                               const void *iv, size_t ivlen)
{
  if (!cms || !oid)
    return gpg_error (GPG_ERR_INV_VALUE);

  xfree (cms->encr_iv);
  cms->encr_iv = NULL;
  cms->encr_ivlen = 0;

  if (0 == strncmp (oid, "1.2.643.2.2.31.", 15) ||
      0 == strcmp (oid, "1.2.643.7.1.2.5.1.1"))
    {
      /* GOST-28147 S-box. Set both the algo OID and the S-box OID. */
      cms->encr_algo_oid = xtrystrdup ("1.2.643.2.2.21");
      cms->encr_algo_sbox_oid = xtrystrdup (oid);
    }
  else
    {
      cms->encr_algo_oid = xtrystrdup (oid);
      /* Clear the S-box if any. */
      xfree (cms->encr_algo_sbox_oid);
      cms->encr_algo_sbox_oid = NULL;
    }

  if (!cms->encr_algo_oid)
    return gpg_error (GPG_ERR_ENOMEM);

  if (iv)
    {
      cms->encr_iv = xtrymalloc (ivlen);
      if (!cms->encr_iv)
        return gpg_error (GPG_ERR_ENOMEM);
      memcpy (cms->encr_iv, iv, ivlen);
      cms->encr_ivlen = ivlen;
    }
  return 0;
}

struct algorithm_param_s algo_params_oid = {
  .tag = TYPE_OBJECT_ID,
  .class = CLASS_UNIVERSAL,
  .constructed = 0
};

static gpg_error_t
store_algorithm_id (AsnNode n, const unsigned char *algo,
                    struct algorithm_param_s *algo_params,
                    int algo_params_count)
{
  ksba_writer_t param_wrt = NULL;
  unsigned char *params = NULL;
  size_t paramslen;
  gpg_error_t err = 0;

  if (!algo)
	return gpg_error (GPG_ERR_MISSING_VALUE);

  if (!algo_params)
    {
      if (strcmp (algo, "1.2.643.2.2.19") == 0 ||
          strcmp (algo, "1.2.643.7.1.1.1.1") == 0)
        {
          const unsigned char *oid1_str;
          const unsigned char *oid2_str;
          struct algorithm_param_s def_algo_params[2];
          def_algo_params[0] = algo_params_oid;
          def_algo_params[1] = algo_params_oid;

      	  if (strcmp (algo, "1.2.643.2.2.19") == 0)
            {
              oid1_str = "1.2.643.2.2.35.1";
              oid2_str = "1.2.643.2.2.30.1";
            }
          else /* "1.2.643.7.1.1.1.1" */
            {
              oid1_str = "1.2.643.7.1.2.1.1.1";
              oid2_str = "1.2.643.7.1.1.2.2";
            }
          err = ksba_oid_from_str (oid1_str, &def_algo_params[0].value,
                                   &def_algo_params[0].length);
          if (!err)
            err = ksba_oid_from_str (oid2_str, &def_algo_params[1].value,
                                     &def_algo_params[1].length);

          algo_params = def_algo_params;
          algo_params_count = 2;
        }
    }

  if (err) return err;

  err = ksba_writer_new (&param_wrt);
  if (!err)
	err = ksba_writer_set_mem (param_wrt, 512);
  if (!err)
	err = _ksba_der_write_algorithm_identifier (param_wrt, algo,
												algo_params_count ?
												  algo_params : NULL,
												algo_params_count);
  if (!err)
	{
	  params = ksba_writer_snatch_mem (param_wrt, &paramslen);
	  if (!params)
		err = gpg_error (GPG_ERR_ENOMEM);
	}
  if (!err)
	{
	  n->type = TYPE_PRE_SEQUENCE;
	  err = _ksba_der_store_sequence (n, params + 2, paramslen - 2);
	}

  xfree (params);
  ksba_writer_release (param_wrt);

  return err;
}

static const parsed_values_t *
find_value (const char *name, const parsed_values_t *values, int count)
{
  for (int i = 0; i < count; i++)
    if (0 == strcmp (values[i].name, name))
      return &(values[i]);

  return NULL;
}

static gpg_error_t
transform_gost_values_to_cms (const parsed_values_t *values, int count,
                              struct enc_val_s *enc_val)
{
  AsnNode root, n;
  ksba_asn_tree_t cms_tree = NULL;
  ksba_writer_t ekey_wrt = NULL;
  unsigned char *ekey_buf = NULL;
  size_t ekey_len;
  unsigned char *tmp2 = NULL;
  gpg_error_t err = 0;

  char *_sbox = NULL;
  char *_digest_oid = NULL;
  char *_curve = NULL;
  char *_ukm = NULL;

  /* Required arguments */
  const parsed_values_t *q = find_value ("q", values, count);
  if (!q || !q->value) return gpg_error (GPG_ERR_INV_ARG);
  const parsed_values_t *ukm = find_value ("ukm", values, count);
  if (!ukm || !ukm->value) return gpg_error (GPG_ERR_INV_ARG);
  const parsed_values_t *ciphertext = find_value ("s", values, count);
  if (!ciphertext || !ciphertext->value) return gpg_error (GPG_ERR_INV_ARG);
  const parsed_values_t *curve = find_value ("curve", values, count);
  if (!curve || !curve->value) return gpg_error (GPG_ERR_INV_ARG);
  const parsed_values_t *sbox = find_value ("sbox", values, count);
  if (!sbox || !sbox->value) return gpg_error (GPG_ERR_INV_ARG);

  /* Optional arguments */
  const parsed_values_t *algo = find_value ("algo", values, count);
  const parsed_values_t *digest = find_value ("digest", values, count);

  if (ciphertext->len != 32 + 4 || ((q->len % 2) && *(q->value) != 0x04))
	return gpg_error (GPG_ERR_INV_VALUE);

  err = ksba_asn_create_tree ("cms", &cms_tree);
  if (err) return err;

  root = _ksba_asn_expand_tree (cms_tree->parse_tree,
			  "CryptographicMessageSyntax.GostR3410-KeyTransport");

  /* Store the GOST-28147 256-bit key */
  n = _ksba_asn_find_node (root, "GostR3410-KeyTransport.sessionEncryptedKey.encryptedKey");
  if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto exit;
	}
  err = _ksba_der_store_octet_string (n, ciphertext->value, 32);
  if (err) goto exit;

  /* Store the 32-bit MAC */
  n = _ksba_asn_find_node (root, "GostR3410-KeyTransport.sessionEncryptedKey.macKey");
  if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto exit;
	}
  err = _ksba_der_store_octet_string (n, ciphertext->value + 32, 4);
  if (err) goto exit;

  n = _ksba_asn_find_node (root, "GostR3410-KeyTransport.transportParameters..encryptionParamSet");
  if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto exit;
	}
  _sbox = xtrymalloc (sbox->len + 1);
  if (!_sbox)
    {
      err = gpg_error_from_syserror ();
      goto exit;
    }
  memcpy (_sbox, sbox->value, sbox->len);
  _sbox[sbox->len] = '\0';
  err = _ksba_der_store_oid (n, _sbox);
  if (err) goto exit;

  n = _ksba_asn_find_node (root, "GostR3410-KeyTransport.transportParameters..ephemeralPublicKey..algorithm");
  if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto exit;
	}

  if (!enc_val->algo)
    {
      if (algo)
        {
          enc_val->algo = xtrymalloc (algo->len + 1);
          if (!enc_val->algo)
            {
              err = gpg_error_from_syserror ();
              goto exit;
            }
          memcpy (enc_val->algo, algo->value, algo->len);
          enc_val->algo[algo->len] = '\0';
        }
      else
        {
          const char *algo_oid = curve_oid_to_key_algo (curve->value,
                                                        curve->len,
                                                        digest ?
                                                          digest->value : NULL,
                                                        digest ?
                                                        digest->len : 0);
          if (!algo_oid)
            {
              err = gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
              goto exit;
            }
          enc_val->algo = xtrystrdup (algo_oid);
          if (!enc_val->algo)
            {
              err = gpg_error_from_syserror ();
              goto exit;
            }
        }
    }

  const char *digest_oid = NULL;
  if (digest && digest->value)
    {
      _digest_oid = xtrymalloc (digest->len + 1);
      if (!_digest_oid)
        {
          err = gpg_error_from_syserror ();
          goto exit;
        }
      memcpy (_digest_oid, digest->value, digest->len);
      _digest_oid[digest->len] = '\0';
      digest_oid = _digest_oid;
    }
  else
    {
      digest_oid = key_algo_to_digest_algo (enc_val->algo,
                                            strlen (enc_val->algo));
      if (!digest_oid)
        {
          err = gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
          goto exit;
        }
    }

  struct algorithm_param_s pk_algo_params[2];

  _curve = xtrymalloc (curve->len + 1);
  if (!_curve)
    {
      err = gpg_error_from_syserror ();
      goto exit;
    }
  memcpy (_curve, curve->value, curve->len);
  _curve[curve->len] = '\0';
  pk_algo_params[0] = algo_params_oid;
  err = ksba_oid_from_str (_curve, &pk_algo_params[0].value,
                           &pk_algo_params[0].length);
  if (err) goto exit;

  pk_algo_params[1] = algo_params_oid;
  err = ksba_oid_from_str (digest_oid, &pk_algo_params[1].value,
                           &pk_algo_params[1].length);
  if (err) goto exit;

  err = store_algorithm_id (n, enc_val->algo, pk_algo_params, 2);
  if (err) goto exit;

  n = _ksba_asn_find_node (root, "GostR3410-KeyTransport.transportParameters..ephemeralPublicKey..subjectPublicKey");
  if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto exit;
	}

  err = ksba_writer_new (&ekey_wrt);
  if (err) goto exit;

  err = ksba_writer_set_mem (ekey_wrt, 256); // bytes
  if (err) goto exit;

  err = _ksba_ber_write_tl (ekey_wrt, TYPE_OCTET_STRING,
							CLASS_UNIVERSAL, 0,
							(q->len % 2) ? q->len - 1 : q->len);
  if (err) goto exit;

  unsigned int ekey_offs = 0;
  if (q->len % 2)
	ekey_offs = 1; /* Uncompressed point */

  tmp2 = _ksba_xmalloc (q->len - ekey_offs);
  if (!tmp2)
	{
	  err = gpg_error (GPG_ERR_ENOMEM);
	  goto  exit;
	}
  _ksba_flip_ecc_key (q->value + ekey_offs, q->len - ekey_offs, tmp2);

  err = ksba_writer_write (ekey_wrt, tmp2, q->len - ekey_offs);
  if (err) goto exit;

  ekey_buf = ksba_writer_snatch_mem (ekey_wrt, &ekey_len);
  if (!ekey_buf)
	{
	  err = gpg_error (GPG_ERR_ENOMEM);
	  goto exit;
	}

  err = _ksba_der_store_bit_string (n, ekey_buf, ekey_len * 8);
  if (err) goto exit;

  /* Store the UKM */
  n = _ksba_asn_find_node (root, "GostR3410-KeyTransport.transportParameters..ukm");
  if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto exit;
	}

  _ukm = xtrymalloc (ukm->len);
  if (!_ukm)
    {
      err = gpg_error_from_syserror ();
      goto exit;
    }
  /* Put UKM in reverse byte order (LSB) */
  for (int i = 0; i < ukm->len; i++)
    _ukm[i] = ukm->value[ukm->len - 1 - i];
  err = _ksba_der_store_octet_string (n, _ukm, ukm->len);

  if (err) goto exit;

  xfree (enc_val->value);
  err = _ksba_der_encode_tree (root, &enc_val->value, &enc_val->valuelen);

 exit:
  _ksba_asn_release_nodes (root);
  xfree (ekey_buf);
  ksba_writer_release (ekey_wrt);
  ksba_asn_tree_release (cms_tree);
  xfree (tmp2);
  xfree (_sbox);
  xfree (_curve);
  xfree (_digest_oid);
  xfree (_ukm);

  return err;
}

/*
 * encval is expected to be a canonical encoded  S-Exp of this form:
 *  (enc-val
 *	(<algo>
 *	   (<param_name1> <mpi>)
 *	    ...
 *         (<param_namen> <mpi>)
 *         (encr-algo <oid>)
 *         (wrap-algo <oid>)
 *	))
 *
 * Note the <algo> must be given as a stringified OID or the special
 * string "rsa".  For RSA there is just one parameter named "a";
 * encr-algo and wrap-algo are also not used.  For ECC <algo> must be
 * "ecdh" or "gost", the parameter "s" gives the encrypted key, "e"
 * specified  the ephemeral public key, and wrap-algo algo and encr-algo
 * are the stringified OIDs for the ECDH algorithm parameters.  */
gpg_error_t
ksba_cms_set_enc_val (ksba_cms_t cms, int idx, ksba_const_sexp_t encval)
{
  struct certlist_s *cl;
  const unsigned char *s;
  unsigned long n;
  gpg_error_t err = 0;

  enum {
        eUNKNOWN,
        eRSA,
        eECDH,
        eGOST
  } enc_type = eUNKNOWN;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);
  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return gpg_error (GPG_ERR_INV_INDEX); /* No cert to store the value.  */

  /* log_sexp ("encval", encval); */
  s = encval;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;

  if (!(n = snext (&s)))
    return gpg_error (GPG_ERR_INV_SEXP);
  if (!smatch (&s, n, "enc-val"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if (*s != '(')
    return gpg_error (digitp (s)? GPG_ERR_UNKNOWN_SEXP : GPG_ERR_INV_SEXP);
  s++;

  /* Break out the parameters */
  if (!(n = snext (&s)))
    return gpg_error (GPG_ERR_INV_SEXP);

  int value_count = 8;
  parsed_values_t values[value_count];
  memset (values, 0, sizeof (values));

  if (smatch (&s, n, "rsa"))
    {
      err = read_values (&s, NULL, 0, values);
      if (err)
        return err;
      cl->enc_val.algo = xtrystrdup ("1.2.840.113549.1.1.1");
      if (!cl->enc_val.algo)
        {
          err = gpg_error_from_syserror ();
          goto exit;
        }
      enc_type = eRSA;
    }
  else if (smatch (&s, n, "ecdh"))
    {
      enc_type = eECDH;
    }
  else if (smatch (&s, n, "gost"))
    {
      enc_type = eGOST;
    }
  else
    {
      cl->enc_val.algo = xtrymalloc (n+1);
      if (!cl->enc_val.algo)
        {
          err = gpg_error (GPG_ERR_ENOMEM);
          goto exit;
        }
      memcpy (cl->enc_val.algo, s, n);
      cl->enc_val.algo[n] = 0;
      s += n;
    }

  if (cl->enc_val.algo)
    {
      if (!strcmp (cl->enc_val.algo, "1.2.840.113549.1.1.1"))
        enc_type = eRSA;
      else if (!strcmp (cl->enc_val.algo, "1.2.840.10045.2.1"))
        enc_type = eECDH;
      else if (
               /* GOST 2001 */
               !strcmp (sv->algo, "1.2.643.2.2.19")
               /* GOST 2012-256 */
               || !strncmp (sv->algo, "1.2.643.7.1.1.1.1")
               /* GOST 2012-512 */
               || !strncmp (sv->algo, "1.2.643.7.1.1.1.2")
              )
        enc_type = eGOST;
    }

  switch (enc_type)
    {
    case eRSA:
      err = pack_values (values, 0, &cl->enc_val.value, &cl->enc_val.valuelen);
      break;
    case eECDH:
    case eGOST:
      {
        const char * const ec_params[] = { "s", "e", "encr-algo", "curve", "wrap-algo", "digest-algo", "ukm", "sbox" };
        err = read_values (&s, ec_params, value_count, values);
        if (err)
          goto exit;
        if (enc_type == eGOST)
          err = transform_gost_values_to_cms (values, value_count, &cl->enc_val);
        else
          {
            /* Store the "main" parameter into value. */
            const parsed_values_t *s = find_value ("s", values, value_count);
            if (s)
              {
                xfree (cl->enc_val.value);
                cl->enc_val.value = xtrymalloc (s->len);
                if (!cl->enc_val.value)
                  {
                    err =  gpg_error (GPG_ERR_ENOMEM);
                    goto exit;
                  }
                memcpy (cl->enc_val.value, s->value, s->len);
                cl->enc_val.valuelen = s->len;
              }

            /* Store the public key */
            const parsed_values_t *e = find_value ("e", values, value_count);
            if (e)
              {
                xfree (cl->enc_val.ecdh.e);
                cl->enc_val.ecdh.e = xtrymalloc (e->len);
                if (!cl->enc_val.ecdh.e)
                  {
                    err = gpg_error (GPG_ERR_ENOMEM);
                    goto exit;
                  }
                memcpy (cl->enc_val.ecdh.e, e->value, e->len);
                cl->enc_val.ecdh.elen = e->len;
              }

            /* Store the encryption algo string */
            const parsed_values_t *encr_algo = find_value ("encr-algo", values, value_count);
            if (encr_algo)
              {
                xfree (cl->enc_val.ecdh.encr_algo);
                cl->enc_val.ecdh.encr_algo = xtrymalloc (encr_algo->len + 1);
                if (!cl->enc_val.ecdh.encr_algo)
                  {
                    err = gpg_error (GPG_ERR_ENOMEM);
                    goto exit;
                  }
                memcpy (cl->enc_val.ecdh.encr_algo, encr_algo->value, encr_algo->len);
                cl->enc_val.ecdh.encr_algo[encr_algo->len] = 0;
              }

            /* Store the wrap algo string */
            const parsed_values_t *wrap_algo = find_value ("wrap-algo", values, value_count);
            if (wrap_algo)
              {
                xfree (cl->enc_val.ecdh.wrap_algo);
                cl->enc_val.ecdh.wrap_algo = xtrymalloc (wrap_algo->len + 1);
                if (!cl->enc_val.ecdh.wrap_algo)
                  {
                    err = gpg_error (GPG_ERR_ENOMEM);
                    goto exit;
                  }
                memcpy (cl->enc_val.ecdh.wrap_algo, wrap_algo->value, wrap_algo->len);
                cl->enc_val.ecdh.wrap_algo[wrap_algo->len] = 0;
              }
          }

        /* Check that we have all required data.  */
        if (!cl->enc_val.ecdh.e
            || !cl->enc_val.ecdh.elen
            || !cl->enc_val.ecdh.encr_algo
            || !cl->enc_val.ecdh.wrap_algo)
          err = gpg_error (GPG_ERR_INV_SEXP);
      }
      break;
    default:
      err = gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
    }

  if (!cl->enc_val.value)
    err = gpg_error (GPG_ERR_INV_SEXP);

 exit:
  if (err)
    {
      xfree (cl->enc_val.algo);
      xfree (cl->enc_val.value);
      xfree (cl->enc_val.ecdh.wrap_algo);
      xfree (cl->enc_val.ecdh.encr_algo);
      xfree (cl->enc_val.ecdh.e);
    }

  return err;
}




/**
 * ksba_cms_add_recipient:
 * @cms: A CMS object
 * @cert: A certificate used to describe the recipient.
 *
 * This functions starts assembly of a new enveloped data content or adds
 * another recipient to the list of recipients.
 *
 * Note: after successful completion of this function ownership of
 * @cert is transferred to @cms.
 *
 * Return value: 0 on success or an error code.
 **/
gpg_error_t
ksba_cms_add_recipient (ksba_cms_t cms, ksba_cert_t cert)
{
  /* for now we use the same structure */
  return ksba_cms_add_signer (cms, cert);
}




/*
   Content handler for parsing messages
*/

static gpg_error_t
ct_parse_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


static gpg_error_t
ct_parse_signed_data (ksba_cms_t cms)
{
  enum {
    sSTART,
    sGOT_HASH,
    sIN_DATA,
    sERROR
  } state = sERROR;
  ksba_stop_reason_t stop_reason = cms->stop_reason;
  gpg_error_t err = 0;

  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    {
      state = sSTART;
    }
  else if (stop_reason == KSBA_SR_NEED_HASH)
    {
      state = sGOT_HASH;
    }
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      if (!cms->hash_fnc)
        err = gpg_error (GPG_ERR_MISSING_ACTION);
      else
        state = sIN_DATA;
    }
  else if (stop_reason == KSBA_SR_END_DATA)
    {
      state = sGOT_HASH;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = gpg_error (GPG_ERR_INV_STATE);
  else if (stop_reason)
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = _ksba_cms_parse_signed_data_part_1 (cms);
  else if (state == sGOT_HASH)
    err = _ksba_cms_parse_signed_data_part_2 (cms);
  else if (state == sIN_DATA)
    err = read_and_hash_cont (cms);
  else
    err = gpg_error (GPG_ERR_INV_STATE);

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      if (cms->detached_data && !cms->data.digest)
        { /* We use this stop reason to inform the caller about a
             detached signatures.  Actually there is no need for him
             to hash the data now, he can do this also later. */
          stop_reason = KSBA_SR_NEED_HASH;
        }
      else
        { /* The user must now provide a hash function so that we can
             hash the data in the next round */
          stop_reason = KSBA_SR_BEGIN_DATA;
        }
    }
  else if (state == sIN_DATA)
    stop_reason = KSBA_SR_END_DATA;
  else if (state ==sGOT_HASH)
    stop_reason = KSBA_SR_READY;

  cms->stop_reason = stop_reason;
  return 0;
}


static gpg_error_t
ct_parse_enveloped_data (ksba_cms_t cms)
{
  enum {
    sSTART,
    sREST,
    sINDATA,
    sERROR
  } state = sERROR;
  ksba_stop_reason_t stop_reason = cms->stop_reason;
  gpg_error_t err = 0;

  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    {
      state = sSTART;
    }
  else if (stop_reason == KSBA_SR_DETACHED_DATA)
    {
      state = sREST;
    }
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      state = sINDATA;
    }
  else if (stop_reason == KSBA_SR_END_DATA)
    {
      state = sREST;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = gpg_error (GPG_ERR_INV_STATE);
  else if (stop_reason)
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = _ksba_cms_parse_enveloped_data_part_1 (cms);
  else if (state == sREST)
    err = _ksba_cms_parse_enveloped_data_part_2 (cms);
  else if (state == sINDATA)
    err = read_encrypted_cont (cms);
  else
    err = gpg_error (GPG_ERR_INV_STATE);

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      stop_reason = cms->detached_data? KSBA_SR_DETACHED_DATA
                                      : KSBA_SR_BEGIN_DATA;
    }
  else if (state == sINDATA)
    stop_reason = KSBA_SR_END_DATA;
  else if (state ==sREST)
    stop_reason = KSBA_SR_READY;

  cms->stop_reason = stop_reason;
  return 0;
}


static gpg_error_t
ct_parse_digested_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


static gpg_error_t
ct_parse_encrypted_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}



/*
   Content handlers for building messages
*/

static gpg_error_t
ct_build_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}



/* Write everything up to the encapsulated data content type. */
static gpg_error_t
build_signed_data_header (ksba_cms_t cms)
{
  gpg_error_t err;
  unsigned char *buf;
  const char *s;
  size_t len;
  int i;

  /* Write the outer contentInfo. */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->content.oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
  if (err)
    return err;

  /* The SEQUENCE */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;

  /* figure out the CMSVersion to be used */
  if (0 /* fixme: have_attribute_certificates
           || encapsulated_content != data
           || any_signer_info_is_version_3*/ )
    s = "\x03";
  else
    s = "\x01";
  err = _ksba_ber_write_tl (cms->writer, TYPE_INTEGER, CLASS_UNIVERSAL, 0, 1);
  if (err)
    return err;
  err = ksba_writer_write (cms->writer, s, 1);
  if (err)
    return err;

  /* SET OF DigestAlgorithmIdentifier */
  {
    unsigned char *value;
    size_t valuelen;
    ksba_writer_t tmpwrt;

    err = ksba_writer_new (&tmpwrt);
    if (err)
      return err;
    err = ksba_writer_set_mem (tmpwrt, 512);
    if (err)
      {
        ksba_writer_release (tmpwrt);
        return err;
      }

    for (i=0; (s = ksba_cms_get_digest_algo_list (cms, i)); i++)
      {
        int j;
        const char *s2;

        /* (make sure not to write duplicates) */
        for (j=0; j < i && (s2=ksba_cms_get_digest_algo_list (cms, j)); j++)
          {
            if (!strcmp (s, s2))
              break;
          }
        if (j == i)
          {
            err = _ksba_der_write_algorithm_identifier (tmpwrt, s, NULL, 0);
            if (err)
              {
                ksba_writer_release (tmpwrt);
                return err;
              }
          }
      }

    value = ksba_writer_snatch_mem (tmpwrt, &valuelen);
    ksba_writer_release (tmpwrt);
    if (!value)
      {
        err = gpg_error (GPG_ERR_ENOMEM);
        return err;
      }
    err = _ksba_ber_write_tl (cms->writer, TYPE_SET, CLASS_UNIVERSAL,
                              1, valuelen);
    if (!err)
      err = ksba_writer_write (cms->writer, value, valuelen);
    xfree (value);
    if (err)
      return err;
  }



  /* Write the (inner) encapsulatedContentInfo */
  /* if we have a detached signature we don't need to use undefinite
     length here - but it doesn't matter either */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->inner_cont_oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  if ( !cms->detached_data)
    { /* write the tag */
      err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
      if (err)
        return err;
    }

  return err;
}

/* Set the issuer/serial from the cert to the node.
   mode 0: sid
   mode 1: rid
 */
static gpg_error_t
set_issuer_serial (AsnNode info, ksba_cert_t cert, int mode)
{
  gpg_error_t err;
  AsnNode dst, src;

  if (!info || !cert)
    return gpg_error (GPG_ERR_INV_VALUE);

  src = _ksba_asn_find_node (cert->root,
                             "Certificate.tbsCertificate.serialNumber");
  dst = _ksba_asn_find_node (info,
                             mode?
                             "rid.issuerAndSerialNumber.serialNumber":
                             "sid.issuerAndSerialNumber.serialNumber");
  err = _ksba_der_copy_tree (dst, src, cert->image);
  if (err)
    return err;

  src = _ksba_asn_find_node (cert->root,
                             "Certificate.tbsCertificate.issuer");
  dst = _ksba_asn_find_node (info,
                             mode?
                             "rid.issuerAndSerialNumber.issuer":
                             "sid.issuerAndSerialNumber.issuer");
  err = _ksba_der_copy_tree (dst, src, cert->image);
  if (err)
    return err;

  return 0;
}


/* Store the sequence of capabilities at NODE */
static gpg_error_t
store_smime_capability_sequence (AsnNode node,
                                 struct oidparmlist_s *capabilities)
{
  gpg_error_t err;
  struct oidparmlist_s *cap, *cap2;
  unsigned char *value;
  size_t valuelen;
  ksba_writer_t tmpwrt;

  err = ksba_writer_new (&tmpwrt);
  if (err)
    return err;
  err = ksba_writer_set_mem (tmpwrt, 512);
  if (err)
    {
      ksba_writer_release (tmpwrt);
      return err;
    }

  for (cap=capabilities; cap; cap = cap->next)
    {
      /* (avoid writing duplicates) */
      for (cap2=capabilities; cap2 != cap; cap2 = cap2->next)
        {
          if (!strcmp (cap->oid, cap2->oid)
              && cap->parmlen && cap->parmlen == cap2->parmlen
              && !memcmp (cap->parm, cap2->parm, cap->parmlen))
            break; /* Duplicate found. */
        }
      if (cap2 == cap)
        {
          /* RFC3851 requires that a missing parameter must not be
             encoded as NULL.  This is in contrast to all other usages
             of the algorithm identifier where ist is allowed and in
             some profiles (e.g. tmttv2) even explicitly suggested to
             use NULL.  */
		  struct algorithm_param_s param = {
			.tag = TYPE_OCTET_STRING,
			.class = CLASS_UNIVERSAL,
			.constructed = 0,
			.value = cap->parmlen ? cap->parm : (unsigned char *) "",
			.length = cap->parmlen
		  };
          err = _ksba_der_write_algorithm_identifier (tmpwrt, cap->oid,
													  &param,
													  cap->parmlen ? 1 : 0);
          if (err)
            {
              ksba_writer_release (tmpwrt);
              return err;
            }
        }
    }

  value = ksba_writer_snatch_mem (tmpwrt, &valuelen);
  if (!value)
    err = gpg_error (GPG_ERR_ENOMEM);
  if (!err)
    err = _ksba_der_store_sequence (node, value, valuelen);
  xfree (value);
  ksba_writer_release (tmpwrt);
  return err;
}


/* An object used to construct the signed attributes. */
struct attrarray_s {
  AsnNode root;
  unsigned char *image;
  size_t imagelen;
};


/* Thank you ASN.1 committee for allowing us to employ a sort to make
   that DER encoding even more complicate. */
static int
compare_attrarray (const void *a_v, const void *b_v)
{
  const struct attrarray_s *a = a_v;
  const struct attrarray_s *b = b_v;
  const unsigned char *ap, *bp;
  size_t an, bn;

  ap = a->image;
  an = a->imagelen;
  bp = b->image;
  bn = b->imagelen;
  for (; an && bn; an--, bn--, ap++, bp++ )
    if (*ap != *bp)
      return *ap - *bp;

  return (an == bn)? 0 : (an > bn)? 1 : -1;
}




/* Write the END of data NULL tag and everything we can write before
   the user can calculate the signature */
static gpg_error_t
build_signed_data_attributes (ksba_cms_t cms)
{
  gpg_error_t err;
  int signer;
  ksba_asn_tree_t cms_tree = NULL;
  struct certlist_s *certlist;
  struct oidlist_s *digestlist;
  struct signer_info_s *si, **si_tail;
  AsnNode root = NULL;
  struct attrarray_s attrarray[4];
  int attridx = 0;
  int i;

  memset (attrarray, 0, sizeof (attrarray));

  /* Write the End tag */
  err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
  if (err)
    return err;

  if (cms->signer_info)
    return gpg_error (GPG_ERR_CONFLICT); /* This list must be empty at
                                            this point. */

  /* Write optional certificates */
  if (cms->cert_info_list)
    {
      unsigned long totallen = 0;
      const unsigned char *der;
      size_t n;

      for (certlist = cms->cert_info_list; certlist; certlist = certlist->next)
        {
          if (!ksba_cert_get_image (certlist->cert, &n))
            return gpg_error (GPG_ERR_GENERAL); /* User passed an
                                                   unitialized cert */
          totallen += n;
        }

      err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, totallen);
      if (err)
        return err;

      for (certlist = cms->cert_info_list; certlist; certlist = certlist->next)
        {
          if (!(der=ksba_cert_get_image (certlist->cert, &n)))
            return gpg_error (GPG_ERR_BUG);
          err = ksba_writer_write (cms->writer, der, n);
          if (err )
            return err;
        }
    }

  /* If we ever support it, here is the right place to do it:
     Write the optional CRLs */

  /* Now we have to prepare the signer info.  For now we will just build the
     signedAttributes, so that the user can do the signature calculation */
  err = ksba_asn_create_tree ("cms", &cms_tree);
  if (err)
    return err;

  certlist = cms->cert_list;
  if (!certlist)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
      goto leave;
    }
  digestlist = cms->digest_algos;
  if (!digestlist)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
      goto leave;
    }

  si_tail = &cms->signer_info;
  for (signer=0; certlist;
       signer++, certlist = certlist->next, digestlist = digestlist->next)
    {
      AsnNode attr;
      AsnNode n;
      unsigned char *image;
      size_t imagelen;

      for (i = 0; i < attridx; i++)
        {
          _ksba_asn_release_nodes (attrarray[i].root);
          xfree (attrarray[i].image);
        }
      attridx = 0;
      memset (attrarray, 0, sizeof (attrarray));

      if (!digestlist)
        {
	  err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
	  goto leave;
	}

      if (!certlist->cert || !digestlist->oid)
	{
	  err = gpg_error (GPG_ERR_BUG);
	  goto leave;
	}

      /* Include the pretty important message digest. */
      attr = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                    "CryptographicMessageSyntax.Attribute");
      if (!attr)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      n = _ksba_asn_find_node (attr, "Attribute.attrType");
      if (!n)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_store_oid (n, oidstr_messageDigest);
      if (err)
        goto leave;
      n = _ksba_asn_find_node (attr, "Attribute.attrValues");
      if (!n || !n->down)
        return gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
      n = n->down; /* fixme: ugly hack */
      assert (certlist && certlist->msg_digest_len);
      err = _ksba_der_store_octet_string (n, certlist->msg_digest,
                                          certlist->msg_digest_len);
      if (err)
        goto leave;
      err = _ksba_der_encode_tree (attr, &image, &imagelen);
      if (err)
        goto leave;
      attrarray[attridx].root = attr;
      attrarray[attridx].image = image;
      attrarray[attridx].imagelen = imagelen;
      attridx++;

      /* Include the content-type attribute. */
      attr = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                    "CryptographicMessageSyntax.Attribute");
      if (!attr)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      n = _ksba_asn_find_node (attr, "Attribute.attrType");
      if (!n)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_store_oid (n, oidstr_contentType);
      if (err)
	goto leave;
      n = _ksba_asn_find_node (attr, "Attribute.attrValues");
      if (!n || !n->down)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      n = n->down; /* fixme: ugly hack */
      err = _ksba_der_store_oid (n, cms->inner_cont_oid);
      if (err)
        goto leave;
      err = _ksba_der_encode_tree (attr, &image, &imagelen);
      if (err)
        goto leave;
      attrarray[attridx].root = attr;
      attrarray[attridx].image = image;
      attrarray[attridx].imagelen = imagelen;
      attridx++;

      /* Include the signing time */
      if (*certlist->signing_time)
        {
          attr = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                     "CryptographicMessageSyntax.Attribute");
          if (!attr)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          n = _ksba_asn_find_node (attr, "Attribute.attrType");
          if (!n)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          err = _ksba_der_store_oid (n, oidstr_signingTime);
          if (err)
            goto leave;
          n = _ksba_asn_find_node (attr, "Attribute.attrValues");
          if (!n || !n->down)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          n = n->down; /* fixme: ugly hack */
          err = _ksba_der_store_time (n, certlist->signing_time);
          if (err)
            goto leave;
          err = _ksba_der_encode_tree (attr, &image, &imagelen);
          if (err)
            goto leave;
          /* We will use the attributes again - so save them */
          attrarray[attridx].root = attr;
          attrarray[attridx].image = image;
          attrarray[attridx].imagelen = imagelen;
          attridx++;
        }

      /* Include the S/MIME capabilities with the first signer. */
      if (cms->capability_list && !signer)
        {
          attr = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                    "CryptographicMessageSyntax.Attribute");
          if (!attr)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          n = _ksba_asn_find_node (attr, "Attribute.attrType");
          if (!n)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          err = _ksba_der_store_oid (n, oidstr_smimeCapabilities);
          if (err)
            goto leave;
          n = _ksba_asn_find_node (attr, "Attribute.attrValues");
          if (!n || !n->down)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          n = n->down; /* fixme: ugly hack */
          err = store_smime_capability_sequence (n, cms->capability_list);
          if (err)
            goto leave;
          err = _ksba_der_encode_tree (attr, &image, &imagelen);
          if (err)
            goto leave;
          attrarray[attridx].root = attr;
          attrarray[attridx].image = image;
          attrarray[attridx].imagelen = imagelen;
          attridx++;
        }

      /* Arggh.  That silly ASN.1 DER encoding rules: We need to sort
         the SET values. */
      qsort (attrarray, attridx, sizeof (struct attrarray_s),
             compare_attrarray);

      /* Now copy them to an SignerInfo tree.  This tree is not
         complete but suitable for ksba_cms_hash_signed_attributes() */
      root = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                    "CryptographicMessageSyntax.SignerInfo");
      n = _ksba_asn_find_node (root, "SignerInfo.signedAttrs");
      if (!n || !n->down)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      /* This is another ugly hack to move to the element we want */
      for (n = n->down->down; n && n->type != TYPE_SEQUENCE; n = n->right)
        ;
      if (!n)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}

      assert (attridx <= DIM (attrarray));
      for (i=0; i < attridx; i++)
        {
          if (i)
            {
              if ( !(n=_ksba_asn_insert_copy (n)))
                {
		  err = gpg_error (GPG_ERR_ENOMEM);
		  goto leave;
		}
            }
          err = _ksba_der_copy_tree (n, attrarray[i].root, attrarray[i].image);
          if (err)
            goto leave;
	  _ksba_asn_release_nodes (attrarray[i].root);
	  free (attrarray[i].image);
	  attrarray[i].root = NULL;
	  attrarray[i].image = NULL;
        }

      err = _ksba_der_encode_tree (root, &image, NULL);
      if (err)
        goto leave;

      si = xtrycalloc (1, sizeof *si);
      if (!si)
        return gpg_error (GPG_ERR_ENOMEM);
      si->root = root;
      root = NULL;
      si->image = image;
      /* Hmmm, we don't set the length of the image. */
      *si_tail = si;
      si_tail = &si->next;
    }

 leave:
  _ksba_asn_release_nodes (root);
  ksba_asn_tree_release (cms_tree);
  for (i = 0; i < attridx; i++)
    {
      _ksba_asn_release_nodes (attrarray[i].root);
      xfree (attrarray[i].image);
    }

  return err;
}




/* The user has calculated the signatures and we can therefore write
   everything left over to do. */
static gpg_error_t
build_signed_data_rest (ksba_cms_t cms)
{
  gpg_error_t err;
  int signer;
  ksba_asn_tree_t cms_tree = NULL;
  struct certlist_s *certlist;
  struct oidlist_s *digestlist;
  struct signer_info_s *si;
  struct sig_val_s *sv;
  ksba_writer_t tmpwrt = NULL;
  AsnNode root = NULL;
  ksba_der_t dbld = NULL;

  /* Now we can really write the signer info */
  err = ksba_asn_create_tree ("cms", &cms_tree);
  if (err)
    return err;

  certlist = cms->cert_list;
  if (!certlist)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
      return err;
    }

  /* To construct the set we use a temporary writer object. */
  err = ksba_writer_new (&tmpwrt);
  if (err)
    goto leave;
  err = ksba_writer_set_mem (tmpwrt, 2048);
  if (err)
    goto leave;

  digestlist = cms->digest_algos;
  si = cms->signer_info;
  sv = cms->sig_val;

  for (signer=0; certlist;
       signer++,
         certlist = certlist->next,
         digestlist = digestlist->next,
         si = si->next,
         sv = sv->next)
    {
      AsnNode n, n2;
      unsigned char *image;
      size_t imagelen;

      if (!digestlist || !si || !sv)
        {
	  err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
	  goto leave;
	}
      if (!certlist->cert || !digestlist->oid)
        {
	  err = gpg_error (GPG_ERR_BUG);
	  goto leave;
	}

      root = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                    "CryptographicMessageSyntax.SignerInfo");

      /* We store a version of 1 because we use the issuerAndSerialNumber */
      n = _ksba_asn_find_node (root, "SignerInfo.version");
      if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_store_integer (n, "\x00\x00\x00\x01\x01");
      if (err)
        goto leave;

      /* Store the sid */
      n = _ksba_asn_find_node (root, "SignerInfo.sid");
      if (!n)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}

      err = set_issuer_serial (n, certlist->cert, 0);
      if (err)
        goto leave;

      /* store the digestAlgorithm */
      n = _ksba_asn_find_node (root, "SignerInfo.digestAlgorithm");
      if (!n)
		{
		  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
		  goto leave;
		}
	  err = store_algorithm_id (n, digestlist->oid, NULL, 0);

      /* and the signed attributes */
      n = _ksba_asn_find_node (root, "SignerInfo.signedAttrs");
      if (!n || !n->down)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      assert (si->root);
      assert (si->image);
      n2 = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
      if (!n2 || !n2->down)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_copy_tree (n, n2, si->image);
      if (err)
        goto leave;
      image = NULL;

      /* store the signatureAlgorithm */
      n = _ksba_asn_find_node (root,
			       "SignerInfo.signatureAlgorithm");
      if (!n)
        {
		  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
		  goto leave;
		}
	  err = store_algorithm_id (n, sv->algo, NULL, 0);
      if (err)
		goto leave;

      /* store the signature  */
      if (!sv->value)
        {
	  err = gpg_error (GPG_ERR_MISSING_VALUE);
	  goto leave;
	}
      n = _ksba_asn_find_node (root, "SignerInfo.signature");
      if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}

      err = _ksba_der_store_octet_string (n, sv->value, sv->valuelen);
      if (err)
        goto leave;

      /* Make the DER encoding and write it out. */
      err = _ksba_der_encode_tree (root, &image, &imagelen);
      if (err)
	goto leave;

      err = ksba_writer_write (tmpwrt, image, imagelen);
      xfree (image);
      if (err)
	goto leave;
    }

  /* Write out the SET filled with all signer infos */
  {
    unsigned char *value;
    size_t valuelen;

    value = ksba_writer_snatch_mem (tmpwrt, &valuelen);
    if (!value)
      {
        err = gpg_error (GPG_ERR_ENOMEM);
	goto leave;
      }
    err = _ksba_ber_write_tl (cms->writer, TYPE_SET, CLASS_UNIVERSAL,
                              1, valuelen);
    if (!err)
      err = ksba_writer_write (cms->writer, value, valuelen);
    xfree (value);
    if (err)
      goto leave;
  }

  /* Write 3 end tags */
  err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
  if (!err)
    err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
  if (!err)
    err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);

 leave:
  ksba_asn_tree_release (cms_tree);
  _ksba_asn_release_nodes (root);
  ksba_writer_release (tmpwrt);
  _ksba_der_release (dbld);
  return err;
}




static gpg_error_t
ct_build_signed_data (ksba_cms_t cms)
{
  enum {
    sSTART,
    sDATAREADY,
    sGOTSIG,
    sERROR
  } state = sERROR;
  ksba_stop_reason_t stop_reason;
  gpg_error_t err = 0;

  stop_reason = cms->stop_reason;
  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    {
      state = sSTART;
    }
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      /* fixme: check that the message digest has been set */
      state = sDATAREADY;
    }
  else if (stop_reason == KSBA_SR_END_DATA)
    state = sDATAREADY;
  else if (stop_reason == KSBA_SR_NEED_SIG)
    {
      if (!cms->sig_val)
        err = gpg_error (GPG_ERR_MISSING_ACTION); /* No ksba_cms_set_sig_val () called */
      state = sGOTSIG;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = gpg_error (GPG_ERR_INV_STATE);
  else if (stop_reason)
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    {
      /* figure out whether a detached signature is requested */
      if (cms->cert_list && cms->cert_list->msg_digest_len)
        cms->detached_data = 1;
      else
        cms->detached_data = 0;
      /* and start encoding */
      err = build_signed_data_header (cms);
    }
  else if (state == sDATAREADY)
    {
      if (!cms->detached_data)
        err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
      if (!err)
        err = build_signed_data_attributes (cms);
    }
  else if (state == sGOTSIG)
    err = build_signed_data_rest (cms);
  else
    err = gpg_error (GPG_ERR_INV_STATE);

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      /* user should write the data and calculate the hash or do
         nothing in case of END_DATA */
      stop_reason = cms->detached_data? KSBA_SR_END_DATA
                                      : KSBA_SR_BEGIN_DATA;
    }
  else if (state == sDATAREADY)
    stop_reason = KSBA_SR_NEED_SIG;
  else if (state == sGOTSIG)
    stop_reason = KSBA_SR_READY;

  cms->stop_reason = stop_reason;
  return 0;
}


/* write everything up to the encryptedContentInfo including the tag */
static gpg_error_t
build_enveloped_data_header (ksba_cms_t cms)
{
  gpg_error_t err;
  int recpno;
  struct certlist_s *certlist;
  unsigned char *buf;
  const char *s;
  size_t len;
  ksba_der_t dbld = NULL;
  int any_ecdh = 0;

  /* See whether we have any ECDH recipients.  */
  for (certlist = cms->cert_list; certlist; certlist = certlist->next)
    if (certlist->enc_val.ecdh.e)
      {
        any_ecdh = 1;
        break;
      }

  /* Write the outer contentInfo */
  /* fixme: code is shared with signed_data_header */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->content.oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
  if (err)
    return err;

  /* The SEQUENCE */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;

  /* figure out the CMSVersion to be used (from rfc2630):
     version is the syntax version number.  If originatorInfo is
     present, then version shall be 2.  If any of the RecipientInfo
     structures included have a version other than 0, then the version
     shall be 2.  If unprotectedAttrs is present, then version shall
     be 2.  If originatorInfo is absent, all of the RecipientInfo
     structures are version 0, and unprotectedAttrs is absent, then
     version shall be 0.

     For SPHINX the version number must be 0.
  */


  s = any_ecdh? "\x02" :"\x00";
  err = _ksba_ber_write_tl (cms->writer, TYPE_INTEGER, CLASS_UNIVERSAL, 0, 1);
  if (err)
    return err;
  err = ksba_writer_write (cms->writer, s, 1);
  if (err)
    return err;

  /* Note: originatorInfo is not yet implemented and must not be used
     for SPHINX */

  certlist = cms->cert_list;
  if (!certlist)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
      goto leave;
    }


  dbld = _ksba_der_builder_new (0);
  if (!dbld)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  _ksba_der_add_tag (dbld, 0, TYPE_SET);
  for (recpno=0; certlist; recpno++, certlist = certlist->next)
    {
      const unsigned char *der;
      size_t derlen;

      if (!certlist->cert)
        {
          err = gpg_error (GPG_ERR_BUG);
          goto leave;
        }

      if (!certlist->enc_val.ecdh.e)  /* RSA or GOST (ktri) */
        {
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          /* We store a version of 0 because we are only allowed to
           * use the issuerAndSerialNumber for SPHINX */
          _ksba_der_add_ptr (dbld, 0, TYPE_INTEGER, "", 1);
          /* rid.issuerAndSerialNumber */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          /* rid.issuerAndSerialNumber.issuer */
          err = _ksba_cert_get_issuer_dn_ptr (certlist->cert, &der, &derlen);
          if (err)
            goto leave;
          _ksba_der_add_der (dbld, der, derlen);
          /* rid.issuerAndSerialNumber.serialNumber */
          err = _ksba_cert_get_serial_ptr (certlist->cert, &der, &derlen);
          if (err)
            goto leave;
          _ksba_der_add_der (dbld, der, derlen);
          _ksba_der_add_end (dbld);

          /* Store the keyEncryptionAlgorithm */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          if (!certlist->enc_val.algo || !certlist->enc_val.value)
            {
              err = gpg_error (GPG_ERR_MISSING_VALUE);
              goto leave;
            }
          _ksba_der_add_oid (dbld, certlist->enc_val.algo);
          /* Now store NULL for the optional parameters.  From Peter
           * Gutmann's X.509 style guide:
           *
           *   Another pitfall to be aware of is that algorithms which
           *   have no parameters have this specified as a NULL value
           *   rather than omitting the parameters field entirely.  The
           *   reason for this is that when the 1988 syntax for
           *   AlgorithmIdentifier was translated into the 1997 syntax,
           *   the OPTIONAL associated with the AlgorithmIdentifier
           *   parameters got lost.  Later it was recovered via a defect
           *   report, but by then everyone thought that algorithm
           *   parameters were mandatory.  Because of this the algorithm
           *   parameters should be specified as NULL, regardless of what
           *   you read elsewhere.
           *
           *        The trouble is that things *never* get better, they just
           *        stay the same, only more so
           *            -- Terry Pratchett, "Eric"
           *
           * Although this is about signing, we always do it.  Versions of
           * Libksba before 1.0.6 had a bug writing out the NULL tag here,
           * thus in reality we used to be correct according to the
           * standards despite we didn't intended so.
           */
          _ksba_der_add_ptr (dbld, 0, TYPE_NULL, NULL, 0);
          _ksba_der_add_end (dbld);

          /* Store the encryptedKey  */
          if (!certlist->enc_val.value)
            {
              err = gpg_error (GPG_ERR_MISSING_VALUE);
              goto leave;
            }
          _ksba_der_add_ptr (dbld, 0, TYPE_OCTET_STRING,
                             certlist->enc_val.value,
                             certlist->enc_val.valuelen);

        }
      else /* ECDH */
        {
          _ksba_der_add_tag (dbld, CLASS_CONTEXT, 1); /* kari */
          _ksba_der_add_ptr (dbld, 0, TYPE_INTEGER, "\x03", 1);

          _ksba_der_add_tag (dbld, CLASS_CONTEXT, 0); /* originator */
          _ksba_der_add_tag (dbld, CLASS_CONTEXT, 1); /* originatorKey */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* algorithm */
          _ksba_der_add_oid (dbld, certlist->enc_val.algo);
          _ksba_der_add_end (dbld);
          _ksba_der_add_bts (dbld, certlist->enc_val.ecdh.e,
                             certlist->enc_val.ecdh.elen, 0);
          _ksba_der_add_end (dbld); /* end originatorKey */
          _ksba_der_add_end (dbld); /* end originator */

          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* keyEncrAlgo */
          _ksba_der_add_oid (dbld, certlist->enc_val.ecdh.encr_algo);
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          _ksba_der_add_oid (dbld, certlist->enc_val.ecdh.wrap_algo);
          _ksba_der_add_end (dbld);
          _ksba_der_add_end (dbld); /* end keyEncrAlgo */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* recpEncrKeys */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* recpEncrKey */

          /* rid.issuerAndSerialNumber */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          err = _ksba_cert_get_issuer_dn_ptr (certlist->cert, &der, &derlen);
          if (err)
            goto leave;
          _ksba_der_add_der (dbld, der, derlen);
          err = _ksba_cert_get_serial_ptr (certlist->cert, &der, &derlen);
          if (err)
            goto leave;
          _ksba_der_add_der (dbld, der, derlen);
          _ksba_der_add_end (dbld);

          /* encryptedKey  */
          if (!certlist->enc_val.value)
            {
              err = gpg_error (GPG_ERR_MISSING_VALUE);
              goto leave;
            }
          _ksba_der_add_ptr (dbld, 0, TYPE_OCTET_STRING,
                             certlist->enc_val.value,
                             certlist->enc_val.valuelen);

          _ksba_der_add_end (dbld); /* end recpEncrKey */
          _ksba_der_add_end (dbld); /* end recpEncrKeys */
       }

      _ksba_der_add_end (dbld); /* End SEQUENCE (ktri or kari) */
    }
  _ksba_der_add_end (dbld);  /* End SET */

  /* Write out the SET filled with all recipient infos */
  {
    unsigned char *image;
    size_t imagelen;

    err = _ksba_der_builder_get (dbld, &image, &imagelen);
    if (err)
      goto leave;
    err = ksba_writer_write (cms->writer, image, imagelen);
    xfree (image);
    if (err)
      goto leave;
  }

  /* Write the (inner) encryptedContentInfo */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->inner_cont_oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  struct algorithm_param_s algo_params[2];
  int algo_params_count = 1;
  struct algorithm_param_s algo_params_iv = {
	.tag = TYPE_OCTET_STRING,
	.class = CLASS_UNIVERSAL,
	.constructed = 0,
	.value = cms->encr_iv,
	.length = cms->encr_ivlen
  };
  algo_params[0] = algo_params_iv;

  if (0 == strcmp (cms->encr_algo_oid, "1.2.643.2.2.21")
      && cms->encr_algo_sbox_oid)
	{
	  algo_params[1] = algo_params_oid;
	  err = ksba_oid_from_str (cms->encr_algo_sbox_oid, &algo_params[1].value,
							   &algo_params[1].length);
	  if (err) return err;
	  algo_params_count = 2;
	}

  /* and the encryptionAlgorithm */
  err = _ksba_der_write_algorithm_identifier (cms->writer,
                                              cms->encr_algo_oid,
											  algo_params,
											  algo_params_count);
  if (err)
    return err;

  /* write the tag for the encrypted data, it is an implicit octect
     string in constructed form and indefinite length */
  err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
  if (err)
    return err;

  /* Now the encrypted data should be written */

 leave:
  _ksba_der_release (dbld);
  return err;
}


static gpg_error_t
ct_build_enveloped_data (ksba_cms_t cms)
{
  enum {
    sSTART,
    sINDATA,
    sREST,
    sERROR
  } state = sERROR;
  ksba_stop_reason_t stop_reason;
  gpg_error_t err = 0;

  stop_reason = cms->stop_reason;
  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    state = sSTART;
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    state = sINDATA;
  else if (stop_reason == KSBA_SR_END_DATA)
    state = sREST;
  else if (stop_reason == KSBA_SR_RUNNING)
    err = gpg_error (GPG_ERR_INV_STATE);
  else if (stop_reason)
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = build_enveloped_data_header (cms);
  else if (state == sINDATA)
    err = write_encrypted_cont (cms);
  else if (state == sREST)
    {
      /* SPHINX does not allow for unprotectedAttributes */

      /* Write 5 end tags */
      err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
      if (!err)
        err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
      if (!err)
        err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
      if (!err)
        err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
    }
  else
    err = gpg_error (GPG_ERR_INV_STATE);

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    { /* user should now write the encrypted data */
      stop_reason = KSBA_SR_BEGIN_DATA;
    }
  else if (state == sINDATA)
    { /* tell the user that we wrote everything */
      stop_reason = KSBA_SR_END_DATA;
    }
  else if (state == sREST)
    {
      stop_reason = KSBA_SR_READY;
    }

  cms->stop_reason = stop_reason;
  return 0;
}


static gpg_error_t
ct_build_digested_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


static gpg_error_t
ct_build_encrypted_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}
