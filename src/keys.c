#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "config.h"
#include "backend.h"

int
main(int argc, const char **argv)
{
  int rc = 0;
  char* pubkey = NULL;

  if( argc < 2 ){ fprintf(stderr, "Usage: %s user\n", argv[0]); return 1; }

  D("Reading config file: %s", CFGFILE);
  if(!loadconfig(CFGFILE)){ D("Can't read config"); rc = 2; goto SKIP; }
  
  D("Fetching the public key of user %s", argv[1]);
  rc = backend_get_item(argv[1], PUBKEY, &pubkey);

  if(!pubkey || rc < 0){ rc = 3; goto SKIP; }

  rc = !(printf("%s", pubkey) > 0);
SKIP:
  cleanconfig();
  if(pubkey)free(pubkey);
  return rc;
}



