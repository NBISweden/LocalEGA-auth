#include <stdio.h>

#include "utils.h"
#include "backend.h"

int
main(int argc, const char **argv)
{
  int rc = 0;
  _cleanup_str_ char* pubkey = NULL;

  if( argc < 2 ){ fprintf(stderr, "Usage: %s user\n", argv[0]); return 1; }

  if( !backend_opened() ){ D1("Backend not usable"); return 2; }
  
  D1("Fetching the public key of %s", argv[1]);
  rc = backend_get_pubkey(argv[1], &pubkey);

  if(!pubkey || rc < 0){ return 3; }

  printf("%s", pubkey);
  return 0;
}



