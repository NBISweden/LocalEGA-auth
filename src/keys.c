#include <stdio.h>
#include <sys/types.h>

#include "utils.h"
#include "backend.h"
#include "cega.h"

int
main(int argc, const char **argv)
{
  int rc = 0;
  _cleanup_str_ char* pubkey = NULL;
  const char* username = argv[1];

  if( argc < 2 ){ fprintf(stderr, "Usage: %s user\n", argv[0]); return 1; }

  D1("Fetching the public key of %s", username);

  /* check database */
  bool use_backend = backend_opened();
  if(use_backend){
    if(backend_print_pubkey(username)) return rc;
  } else {
    PROGRESS("Not using the cache");
  }

  /* Defining the CentralEGA callback */
  int print_pubkey(uid_t uid, char* password_hash, char* pubkey, char* gecos){
    int rc = 1;
    if(pubkey){ printf("%s", pubkey); rc = 0; /* success */ }
    if(use_backend && backend_add_user(username, uid, password_hash, pubkey, gecos)); // ignore
    return rc;
  }

  return cega_get_username(username, print_pubkey);
}
