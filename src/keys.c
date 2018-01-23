#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "config.h"
#include "backend.h"

int
main(int argc, const char **argv)
{
  int rc = 0;
  _cleanup_str_ char* pubkey = NULL;

  if( argc < 2 ){ fprintf(stderr, "Usage: %s user\n", argv[0]); return 1; }

  if( config_not_loaded() ){ D1("Config not loaded"); return 2; }
  
  D1("Fetching the public key of %s", argv[1]);
  rc = backend_get_item(argv[1], PUBKEY, &pubkey);

  if(!pubkey || rc < 0){ return 3; }

  printf("%s", pubkey);
  return 0;
}



