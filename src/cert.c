/* cert.c - main function for the certificate handling
 *      Copyright (C) 2001 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * KSBA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "ber-decoder.h"
#include "ber-help.h"
#include "convert.h"
#include "keyinfo.h"
#include "cert.h"


/**
 * ksba_cert_new:
 * 
 * Create a new and empty certificate object
 * 
 * Return value: A cert object or NULL in case of memory problems.
 **/
KsbaCert
ksba_cert_new (void)
{
  KsbaCert cert;

  cert = xtrycalloc (1, sizeof *cert);
  if (!cert)
    return NULL;
  cert->ref_count++;

  return cert;
}

void
ksba_cert_ref (KsbaCert cert)
{
  if (!cert)
    fprintf (stderr, "BUG: ksba_cert_ref for NULL\n");
  else
    ++cert->ref_count;
}

/**
 * ksba_cert_release:
 * @cert: A certificate object
 * 
 * Release a certificate object.
 **/
void
ksba_cert_release (KsbaCert cert)
{
  int i;

  if (!cert)
    return;
  if (cert->ref_count < 1)
    {
      fprintf (stderr, "BUG: trying to release an already released cert\n");
      return;
    }
  if (--cert->ref_count)
    return;

  xfree (cert->cache.digest_algo);
  if (cert->cache.extns_valid)
    {
      for (i=0; i < cert->cache.n_extns; i++)
        xfree (cert->cache.extns[i].oid);
      xfree (cert->cache.extns);
    }

  /* FIXME: release cert->root, ->asn_tree */
  xfree (cert);
}


/**
 * ksba_cert_read_der:
 * @cert: An unitialized certificate object
 * @reader: A KSBA Reader object
 * 
 * Read the next certificate from the reader and store it in the
 * certificate object for future access.  The certificate is parsed
 * and rejected if it has any syntactical or semantical error
 * (i.e. does not match the ASN.1 description).
 * 
 * Return value: 0 on success or an error value
 **/
KsbaError
ksba_cert_read_der (KsbaCert cert, KsbaReader reader)
{
  KsbaError err = 0;
  BerDecoder decoder = NULL;

  if (!cert || !reader)
    return KSBA_Invalid_Value;
  if (cert->initialized)
    return KSBA_Conflict; /* FIXME: should remove the old one */

  /* fixme: clear old cert->root */

  err = ksba_asn_create_tree ("tmttv2", &cert->asn_tree);
  if (err)
    goto leave;

  decoder = _ksba_ber_decoder_new ();
  if (!decoder)
    {
      err = KSBA_Out_Of_Core;
      goto leave;
    }

  err = _ksba_ber_decoder_set_reader (decoder, reader);
  if (err)
    goto leave;
  
  err = _ksba_ber_decoder_set_module (decoder, cert->asn_tree);
  if (err)
     goto leave;

  err = _ksba_ber_decoder_decode (decoder, "TMTTv2.Certificate",
                                  &cert->root, &cert->image, &cert->imagelen);
  if (!err)
      cert->initialized = 1;
  
 leave:
  _ksba_ber_decoder_release (decoder);

  return err;
}


KsbaError
ksba_cert_init_from_mem (KsbaCert cert, const void *buffer, size_t length)
{
  KsbaError err;
  KsbaReader reader;

  reader = ksba_reader_new ();
  if (!reader)
    return KSBA_Out_Of_Core;
  err = ksba_reader_set_mem (reader, buffer, length);
  if (err)
    {
      ksba_reader_release (reader);
      return err;
    }
  err = ksba_cert_read_der (cert, reader);
  ksba_reader_release (reader);
  return err;
}



const unsigned char *
ksba_cert_get_image (KsbaCert cert, size_t *r_length )
{
  AsnNode n;

  if (!cert)
    return NULL;
  if (!cert->initialized)
    return NULL;

  n = _ksba_asn_find_node (cert->root, "Certificate");
  if (!n) 
    return NULL;

  if (n->off == -1)
    {
      fputs ("ksba_cert_get_image problem at node:\n", stderr);
      _ksba_asn_node_dump_all (n, stderr);
      return NULL;
    }

  if (r_length)
    *r_length = cert->imagelen;
  return cert->image;
}


KsbaError
ksba_cert_hash (KsbaCert cert, int what,
                void (*hasher)(void *, const void *, size_t length), 
                void *hasher_arg)
{
  AsnNode n;

  if (!cert /*|| !hasher*/)
    return KSBA_Invalid_Value;
  if (!cert->initialized)
    return KSBA_No_Data;

  n = _ksba_asn_find_node (cert->root,
                           what == 1? "Certificate.tbsCertificate"
                                    : "Certificate");
  if (!n)
    return KSBA_No_Value; /* oops - should be there */
  if (n->off == -1)
    {
      fputs ("ksba_cert_hash problem at node:\n", stderr);
      _ksba_asn_node_dump_all (n, stderr);
      return KSBA_No_Value;
    }

  hasher (hasher_arg, cert->image + n->off,  n->nhdr + n->len);


  return 0;
}


/**
 * ksba_cert_get_digest_algo:
 * @cert: Initialized certificate object
 * 
 * Figure out the the digest algorithm used for the signature and
 * return its OID
 *
 * This function is intended as a helper for the ksba_cert_hash().
 * 
 * Return value: NULL for error otherwise a constant string with the OID.
 * This string is valid as long the certificate object is valid.
 **/
const char *
ksba_cert_get_digest_algo (KsbaCert cert)
{
  AsnNode n;
  char *algo;

  if (!cert)
    {
       cert->last_error = KSBA_Invalid_Value;
       return NULL;
    }
  if (!cert->initialized)
    {
       cert->last_error = KSBA_No_Data;
       return NULL;
    }

  if (cert->cache.digest_algo)
    return cert->cache.digest_algo;
  
  n = _ksba_asn_find_node (cert->root,
                           "Certificate.signatureAlgorithm.algorithm");
  algo = _ksba_oid_node_to_str (cert->image, n);
  if (!algo)
    cert->last_error = KSBA_Unknown_Algorithm;
  else 
    cert->cache.digest_algo = algo;

  return algo;
}




/**
 * ksba_cert_get_serial:
 * @cert: certificate object 
 * 
 * This function returnes the serial number of the certificate.  The
 * serial number is an integer returned as an cancnical encoded
 * S-expression with just one element.
 * 
 * Return value: An allocated S-Exp or NULL for no value.
 **/
KsbaSexp
ksba_cert_get_serial (KsbaCert cert)
{
  AsnNode n;
  char *p;
  char numbuf[22];
  int numbuflen;

  if (!cert || !cert->initialized)
    return NULL;
  
  n = _ksba_asn_find_node (cert->root,
                           "Certificate.tbsCertificate.serialNumber");
  if (!n)
    return NULL; /* oops - should be there */

  if (n->off == -1)
    {
      fputs ("get_serial problem at node:\n", stderr);
      _ksba_asn_node_dump_all (n, stderr);
      return NULL;
    }
  
  sprintf (numbuf,"(%u:", (unsigned int)n->len);
  numbuflen = strlen (numbuf);
  p = xtrymalloc (numbuflen + n->len + 2);
  if (!p)
    return NULL;
  strcpy (p, numbuf);
  memcpy (p+numbuflen, cert->image + n->off + n->nhdr, n->len);
  p[numbuflen + n->len] = ')';
  p[numbuflen + n->len + 1] = 0;
  return p;
}

/**
 * ksba_cert_get_issuer:
 * @cert: certificate object
 * 
 * With @idx == 0 this function returns the Distinguished Name (DN) of
 * the certificate issuer which in most cases is a CA.  The format of
 * the returned string is in accordance with RFC-2253.  NULL is
 * returned if the DN is not available which is an error and should
 * have been catched by the certificate reading function.
 * 
 * With @idx > 0 the function may be used to enumerate alternate
 * issuer names. The function returns NULL if there are no more
 * alternate names.  The function does only return alternate names
 * which are recognized by libksba and ignores others.  The format of
 * the returned name is either a RFC-2253 formated one which can be
 * detected by checking whether the first character is letter or
 * digit.  rfc-2822 conform email addresses are returned enclosed in
 * angle brackets, the opening angle bracket should be used to
 * indicate this.  Other formats are returned as an S-Expression in
 * canonical format, so a opening parenthesis may be used to detect
 * this encoding, the name may include binary null characters, so
 * strlen may return a legth shorther than actually used, the real
 * length is implictly given by the structure of the S-Exp, an extra
 * null is appended to make debugging output easier.
 * 
 * The caller must free the returned string using ksba_free() or the
 * function he has registered as a replacement.
 * 
 * Return value: An allocated string or NULL for error.
 **/
char *
ksba_cert_get_issuer (KsbaCert cert, int idx)
{
  KsbaError err;
  AsnNode n;
  char *p;

  if (!cert || !cert->initialized)
    return NULL;
  if (idx)
    return NULL;
  
  n = _ksba_asn_find_node (cert->root,
                           "Certificate.tbsCertificate.issuer");
  if (!n || !n->down)
    return NULL; /* oops - should be there */
  n = n->down; /* dereference the choice node */

  if (n->off == -1)
    {
      fputs ("get_issuer problem at node:\n", stderr);
      _ksba_asn_node_dump_all (n, stderr);
      return NULL;
    }
  err = _ksba_dn_to_str (cert->image, n, &p);
  if (err)
    {
      cert->last_error = err;
      return NULL;
    }
  return p;
}



/**
 * ksba_cert_get_valididy:
 * @cert: cetificate object
 * @what: 0 for notBefore, 1 for notAfter
 * 
 * Return the validity object from the certificate.  If no value is
 * available 0 is returned because we can safely assume that this is
 * not a valid date.
 * 
 * Return value: seconds since epoch, 0 for no value or (time)-1 for error.
 **/
time_t
ksba_cert_get_validity (KsbaCert cert, int what)
{
  AsnNode n, n2;
  time_t t;

  if (!cert || what < 0 || what > 1)
    return (time_t)(-1);
  if (!cert->initialized)
    return (time_t)(-1);
  
  n = _ksba_asn_find_node (cert->root,
        what == 0? "Certificate.tbsCertificate.validity.notBefore"
                 : "Certificate.tbsCertificate.validity.notAfter");
  if (!n)
    return 0; /* no value available */

  /* FIXME: We should remove the choice node and don't use this ugly hack */
  for (n2=n->down; n2; n2 = n2->right)
    {
      if ((n2->type == TYPE_UTC_TIME || n2->type == TYPE_GENERALIZED_TIME)
          && n2->off != -1)
        break;
    }
  n = n2;
  if (!n)
    return 0; /* no value available */

  return_val_if_fail (n->off != -1, (time_t)(-1));

  t = _ksba_asntime_to_epoch (cert->image + n->off + n->nhdr, n->len);
  if (!t) /* we consider this an error */
    t = (time_t)(-1);
  return t;
}


/* See ..get_issuer */
char *
ksba_cert_get_subject (KsbaCert cert, int idx)
{
  KsbaError err;
  AsnNode n;
  char *p;

  if (!cert || !cert->initialized)
    return NULL;
  if (idx)
    return NULL;
  
  n = _ksba_asn_find_node (cert->root,
                           "Certificate.tbsCertificate.subject");
  if (!n || !n->down)
    return NULL; /* oops - should be there */
  n = n->down; /* dereference the choice node */

  if (n->off == -1)
    {
      fputs ("get_issuer problem at node:\n", stderr);
      _ksba_asn_node_dump_all (n, stderr);
      return NULL;
    }
  err = _ksba_dn_to_str (cert->image, n, &p);
  if (err)
    {
      cert->last_error = err;
      return NULL;
    }
  return p;
}


KsbaSexp
ksba_cert_get_public_key (KsbaCert cert)
{
  AsnNode n;
  KsbaError err;
  KsbaSexp string;

  if (!cert)
    return NULL;
  if (!cert->initialized)
    return NULL;

  n = _ksba_asn_find_node (cert->root,
                           "Certificate"
                           ".tbsCertificate.subjectPublicKeyInfo");
  if (!n)
    {
      cert->last_error = KSBA_No_Value;
      return NULL;
    }

  err = _ksba_keyinfo_to_sexp (cert->image + n->off, n->nhdr + n->len,
                               &string);
  if (err)
    {
      cert->last_error = err;
      return NULL;
    }

  return string;
}

KsbaSexp
ksba_cert_get_sig_val (KsbaCert cert)
{
  AsnNode n, n2;
  KsbaError err;
  KsbaSexp string;

  if (!cert)
    return NULL;
  if (!cert->initialized)
    return NULL;

  n = _ksba_asn_find_node (cert->root,
                           "Certificate.signatureAlgorithm");
  if (!n)
    {
      cert->last_error = KSBA_No_Value;
      return NULL;
    }
  if (n->off == -1)
    {
      fputs ("ksba_cert_get_sig_val problem at node:\n", stderr);
      _ksba_asn_node_dump_all (n, stderr);
      cert->last_error = KSBA_No_Value;
      return NULL;
    }

  n2 = n->right;
  err = _ksba_sigval_to_sexp (cert->image + n->off,
                              n->nhdr + n->len
                              + ((!n2||n2->off == -1)? 0:(n2->nhdr+n2->len)),
                              &string);
  if (err)
    {
      cert->last_error = err;
      return NULL;
    }

  return string;
}


/* Read all extensions into the cache */
static KsbaError
read_extensions (KsbaCert cert) 
{
  AsnNode start, n;
  int count;

  assert (!cert->cache.extns_valid);
  assert (!cert->cache.extns);

  start = _ksba_asn_find_node (cert->root,
                               "Certificate.tbsCertificate.extensions..");
  for (count=0, n=start; n; n = n->right)
    count++;
  if (!count)
    {
      cert->cache.n_extns = 0;
      cert->cache.extns_valid = 1;
      return 0; /* no extensions at all */
    }
  cert->cache.extns = xtrycalloc (count, sizeof *cert->cache.extns);
  if (!cert->cache.extns)
    return KSBA_Out_Of_Core;
  cert->cache.n_extns = count;

  {
    for (count=0; start; start = start->right, count++)
      {
        n = start->down;
        if (!n || n->type != TYPE_OBJECT_ID)
          goto no_value;
        
        cert->cache.extns[count].oid = _ksba_oid_node_to_str (cert->image, n);
        if (!cert->cache.extns[count].oid)
          goto no_value;
        
        n = n->right;
        if (n && n->type == TYPE_BOOLEAN)
          {
            if (n->off != -1 && n->len && cert->image[n->off + n->nhdr])
              cert->cache.extns[count].crit = 1;
            n = n->right;
          }
        
        if (!n || n->type != TYPE_OCTET_STRING || n->off == -1)
          goto no_value;
        
        cert->cache.extns[count].off = n->off + n->nhdr;
        cert->cache.extns[count].len = n->len;
      }
    
    assert (count == cert->cache.n_extns);
    cert->cache.extns_valid = 1;
    return 0;
    
  no_value:
    for (count=0; count < cert->cache.n_extns; count++)
      xfree (cert->cache.extns[count].oid);
    xfree (cert->cache.extns);
    cert->cache.extns = NULL;
    return KSBA_No_Value;
  }
}


/* Return information about the IDX nth extension */
KsbaError
ksba_cert_get_extension (KsbaCert cert, int idx,
                         char const **r_oid, int *r_crit,
                         size_t *r_deroff, size_t *r_derlen)
{
  KsbaError err;

  if (!cert)
    return KSBA_Invalid_Value;
  if (!cert->initialized)
    return KSBA_No_Data;

  if (!cert->cache.extns_valid)
    {
      err = read_extensions (cert);
      if (err)
        return err;
      assert (cert->cache.extns_valid);
    }

  if (idx == cert->cache.n_extns)
    return -1; /* mo more extensions */

  if (idx < 0 || idx >= cert->cache.n_extns)
    return KSBA_Invalid_Index;
  
  if (r_oid)
    *r_oid = cert->cache.extns[idx].oid;
  if (r_crit)
    *r_crit = cert->cache.extns[idx].crit;
  if (r_deroff)
    *r_deroff = cert->cache.extns[idx].off;
  if (r_derlen)
    *r_derlen = cert->cache.extns[idx].len;
  return 0;
}



/* Return information on the basicConstraint (2.5.19.19) of CERT.
   R_CA receives true if this is a CA and only in that case R_PATHLEN
   is set to the maximim certification path length or -1 if there is
   nosuch limitation */
KsbaError
ksba_cert_is_ca (KsbaCert cert, int *r_ca, int *r_pathlen)
{
  KsbaError err;
  const char *oid;
  int idx, crit;
  size_t off, derlen, seqlen;
  const unsigned char *der;
  struct tag_info ti;
  unsigned long value;

  /* set default values */
  if (r_ca)
    *r_ca = 0;
  if (r_pathlen)
    *r_pathlen = -1;
  for (idx=0; !(err=ksba_cert_get_extension (cert, idx, &oid, &crit,
                                             &off, &derlen)); idx++)
    {
      if (!strcmp (oid, "2.5.29.19"))
        break;
    }
  if (err == -1)
      return 0; /* no such constraint */
  if (err)
    return err;
    
  /* check that there is only one */
  for (idx++; !(err=ksba_cert_get_extension (cert, idx, &oid, NULL,
                                             NULL, NULL)); idx++)
    {
      if (!strcmp (oid, "2.5.29.19"))
        return KSBA_Duplicate_Value; 
    }
  
  der = cert->image + off;
 
  err = _ksba_ber_parse_tl (&der, &derlen, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return KSBA_Invalid_Cert_Object;
  if (ti.ndef)
    return KSBA_Not_DER_Encoded;
  seqlen = ti.length;
  if (seqlen > derlen)
    return KSBA_BER_Error;
  if (!seqlen)
    return 0; /* an empty sequence is allowed because both elements
                 are optional */

  err = _ksba_ber_parse_tl (&der, &derlen, &ti);
  if (err)
    return err;
  if (seqlen < ti.nhdr)
    return KSBA_BER_Error;
  seqlen -= ti.nhdr;
  if (seqlen < ti.length)
    return KSBA_BER_Error; 
  seqlen -= ti.length;

  if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_BOOLEAN)
    { 
      if (ti.length != 1)
        return KSBA_Encoding_Error;
      if (r_ca)
        *r_ca = !!*der;
      der++; derlen--;
      if (!seqlen)
        return 0; /* ready (no pathlength) */

      err = _ksba_ber_parse_tl (&der, &derlen, &ti);
      if (err)
        return err;
      if (seqlen < ti.nhdr)
        return KSBA_BER_Error;
      seqlen -= ti.nhdr;
      if (seqlen < ti.length)
        return KSBA_BER_Error;
      seqlen -= ti.length;
    }

  if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_INTEGER))
    return KSBA_Invalid_Cert_Object;
  
  for (value=0; ti.length; ti.length--)
    {
      value <<= 8;
      value |= (*der++) & 0xff; 
      derlen--;
    }
  if (r_pathlen)
    *r_pathlen = value;

  /* if the extension is marked as critical and any stuff is still
     left we better return an error */
  if (crit && seqlen)
    return KSBA_Invalid_Cert_Object;

  return 0;
}

