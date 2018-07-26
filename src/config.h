
#ifndef __LEGA_CONFIG_H_INCLUDED__
#define __LEGA_CONFIG_H_INCLUDED__

#include <stdbool.h>
#include <sys/types.h> 

#define CFGFILE "/etc/ega/auth.conf"
#define ENABLE_CEGA false
#define CEGA_CERT "/etc/ega/cega.pem"
#define PROMPT "Please, enter your EGA password: "

#define CACHE_TTL 3600.0 // 1h in seconds.
#define RANGE_SHIFT 10000

struct options_s {
  char* cfgfile;
  char* buffer;
  
  gid_t ega_gid;           /* group id for all EGA users */
  double cache_ttl;        /* How long a cache entry is valid (in seconds) */
  int range_shift;         /* added to the user id from CentralEGA */
  char* prompt;            /* Please enter password */

  char* db_connstr;        /* db connection string */

  char* ega_dir;           /* EGA main inbox directory */
  long int ega_dir_attrs;  /* in octal form */
  char* ega_fuse_exec;     /* LegaFS fuse executable */
  char* ega_fuse_flags;    /* Mount flags for fuse directory per user */

  /* Contacting Central EGA (vie REST call) */
  bool with_cega;          /* enable the lookup in case the entry is not found in the database cache */
  char* cega_endpoint;     /* https://central_ega/user/<some-id> | returns a triplet in JSON format */
  char* cega_creds;        /* for authentication: user:password */
  char* cega_json_passwd;  /* Searching with jq for the password field */
  char* cega_json_pubkey;  /* Searching with jq for the public key field */
  char* cega_json_uid;     /* Searching with jq for the user id field */
  char* cega_json_gecos;   /* Searching with jq for the gecos field */
  char* cega_json_shell;   /* Searching with jq for the shell field */
  char* ssl_cert;          /* path the SSL certificate to contact Central EGA */
};

typedef struct options_s options_t;

extern options_t* options;

bool loadconfig(void);
void cleanconfig(void);
bool config_loaded(void);

#endif /* !__LEGA_CONFIG_H_INCLUDED__ */
