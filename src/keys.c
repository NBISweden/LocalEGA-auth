#include <stdio.h>
#include <stdlib.h>

#include "debug.h"
#include "config.h"
#include "backend.h"

int
main(int argc, const char **argv)
{

  int rc = 1;
  char* storage = NULL;

  if( argc < 2 ){
    fprintf(stderr, "Usage: %s user\n", argv[0]);
    goto BAILOUT;
  }

  const char *username = argv[1];
  char *pubkey = NULL;

  D("Fetching keys for user %s", username);

  size_t storage_size = STORAGE_SIZE;
  storage = (char*)malloc( storage_size * sizeof(char) );
  size_t buflen;
  char* buffer;

  if(!storage){ D("Could not allocate a buffer of size %zd", storage_size); rc = -2; goto BAILOUT; }

  if(!backend_open(0)) return false;

INIT:
  buflen = storage_size;
  buffer = storage; /* copy */

  switch( backend_get_item(username, PUBKEY, &pubkey, &buffer, &buflen)) {
  case -1:
    D("Resizing to %zd", storage_size);
    storage_size *= 2;
    D("Resizing to %zd", storage_size);
    if(!realloc(storage, storage_size * sizeof(char))){ D("Could not resize the internal storage"); rc = 2; goto BAILOUT; }
    goto INIT;
    break;
  case -2:
    D("Error with pubkey file for user %s", username);
    goto BAILOUT;
    break;
  default:
    if(!pubkey){ D("could not load the public key for user %s", username); goto BAILOUT; }
    break;
  }
  
  printf("%s\n", pubkey);
  rc = 0;

BAILOUT:
  backend_close();
  if(storage) free(storage);
  return rc;
}
