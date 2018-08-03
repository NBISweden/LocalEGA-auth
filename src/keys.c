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

  REPORT("Fetching the public key of %s", username);

  /* check database */
  bool use_backend = backend_opened();
  if(use_backend && backend_print_pubkey(username)) return rc;

  /* Defining the CentralEGA callback */
  int print_pubkey(char* uname, uid_t uid, char* password_hash, char* pubkey, char* gecos){
    int rc = 1;
    /* assert same name */
    if( strcmp(username, uname) ){
      REPORT("Requested username %s not matching username response %s", username, uname);
      return 1;
    }
    if(pubkey){ printf("%s", pubkey); rc = 0; /* success */ }
    else { REPORT("No ssh key found for user '%s'", username); }
    if(use_backend) backend_add_user(username, uid, password_hash, pubkey, gecos); // ignore result
    return rc;
  }

  return cega_resolve(strjoina(options->cega_endpoint_name, username), print_pubkey);
}
