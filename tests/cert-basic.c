/* cert-basic.c - basic test for the certificate management.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#include "../src/ksba.h"

#define fail_if_err(a) do { if(a) {                                       \
                              fprintf (stderr, "%s:%d: KSBA error: %s\n", \
                              __FILE__, __LINE__, ksba_strerror(a));   \
                              exit (1); }                              \
                           } while(0)


#define fail_if_err2(f, a) do { if(a) {\
            fprintf (stderr, "%s:%d: KSBA error on file `%s': %s\n", \
                       __FILE__, __LINE__, (f), ksba_strerror(a));   \
                            exit (1); }                              \
                           } while(0)


static void *
xmalloc (size_t n)
{
  char *p = ksba_malloc (n);
  if (!p)
    {
      fprintf (stderr, "out of core\n");
      exit (1);
    }
  return p;
}



static void
print_sexp (KsbaConstSexp p)
{
  unsigned long n;
  KsbaConstSexp endp;

  if (!p)
    fputs ("none", stdout);
  else
    {
      n = strtoul (p, (char**)&endp, 10);
      p = endp;
      if (*p!=':')
        fputs ("ERROR - invalid value", stdout);
      else
        {
          for (p++; n; n--, p++)
            printf ("%02X", *p);
        }
    }
}

static void
print_time (time_t t)
{

  if (!t)
    fputs ("none", stdout);
  else if ( t == (time_t)(-1) )
    fputs ("error", stdout);
  else
    {
      struct tm *tp;

      tp = gmtime (&t);
      printf ("%04d-%02d-%02d %02d:%02d:%02d",
              1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
              tp->tm_hour, tp->tm_min, tp->tm_sec);
      assert (!tp->tm_isdst);
    }
}

static void
print_dn (char *p)
{

  if (!p)
    fputs ("error", stdout);
  else
    printf ("`%s'", p);
}


static void
one_file (const char *fname)
{
  KsbaError err;
  FILE *fp;
  KsbaReader r;
  KsbaCert cert;
  char *dn;
  time_t t;
  int idx;
  KsbaSexp sexp;

  fp = fopen (fname, "r");
  if (!fp)
    {
      fprintf (stderr, "%s:%d: can't open `%s': %s\n", 
               __FILE__, __LINE__, fname, strerror (errno));
      exit (1);
    }

  r = ksba_reader_new ();
  if (!r)
    fail_if_err (KSBA_Out_Of_Core);
  err = ksba_reader_set_file (r, fp);
  fail_if_err (err);

  cert = ksba_cert_new ();
  if (!cert)
    fail_if_err (KSBA_Out_Of_Core);

  err = ksba_cert_read_der (cert, r);
  fail_if_err2 (fname, err);

  printf ("Certificate in `%s':\n", fname);

  sexp = ksba_cert_get_serial (cert);
  fputs ("  serial....: ", stdout);
  print_sexp (sexp);
  ksba_free (sexp);
  putchar ('\n');

  for (idx=0;(dn = ksba_cert_get_issuer (cert, idx));idx++) 
    {
      fputs (idx?"         aka: ":"  issuer....:", stdout);
      print_dn (dn);
      ksba_free (dn);
      putchar ('\n');
    }

  for (idx=0;(dn = ksba_cert_get_subject (cert, idx));idx++) 
    {
      fputs (idx?"         aka: ":"  subject....: ", stdout);
      print_dn (dn);
      ksba_free (dn);
      putchar ('\n');
    }

  t = ksba_cert_get_validity (cert, 0);
  fputs ("  notBefore.: ", stdout);
  print_time (t);
  putchar ('\n');
  t = ksba_cert_get_validity (cert, 1);
  fputs ("  notAfter..: ", stdout);
  print_time (t);
  putchar ('\n');

  printf ("  hash algo.: %s\n", ksba_cert_get_digest_algo (cert));


  ksba_cert_release (cert);
  cert = ksba_cert_new ();
  if (!cert)
    fail_if_err (KSBA_Out_Of_Core);

  err = ksba_cert_read_der (cert, r);
  if (err != -1)
    {
      fprintf (stderr, "%s:%d: expected EOF but got: %s\n", 
               __FILE__, __LINE__, ksba_strerror (err));
      exit (1);
    }

  putchar ('\n');
  ksba_cert_release (cert);
  ksba_reader_release (r);
  fclose (fp);
}




int 
main (int argc, char **argv)
{
  const char *srcdir = getenv ("srcdir");
  
  if (!srcdir)
    srcdir = ".";

  if (argc > 1)
    {
      for (argc--, argv++; argc; argc--, argv++)
        one_file (*argv);
    }
  else
    {
      const char *files[] = {
        "cert_dfn_pca01.der",
        "cert_dfn_pca15.der",
        "cert_g10code_test1.der",
        NULL 
      };
      int idx;
      
      for (idx=0; files[idx]; idx++)
        {
          char *fname;

          fname = xmalloc (strlen (srcdir) + 1 + strlen (files[idx]) + 1);
          strcpy (fname, srcdir);
          strcat (fname, "/");
          strcat (fname, files[idx]);
          one_file (fname);
          ksba_free (fname);
        }
    }

  return 0;
}






