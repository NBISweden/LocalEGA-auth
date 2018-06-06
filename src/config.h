#ifndef __LEGA_CONFIG_H_INCLUDED__
#define __LEGA_CONFIG_H_INCLUDED__

#include <stdbool.h>
#include <sys/types.h> 

#define CFGFILE "/etc/ega/auth.conf"
#define ENABLE_CEGA false
#define CEGA_CERT "/etc/ega/cega.pem"
#define PROMPT "Please, enter your EGA password: "
#define EGA_GECOS "EGA User"
#define EGA_SHELL "/sbin/nologin"

#define CACHE_DIR "/ega/cache"
#define CACHE_TTL 3600.0 // 1h in seconds.
#define PUBKEY        "pubkey"
#define PASSWORD      "pwd"
#define LAST_ACCESSED "last"

struct options_s {
  char* cfgfile;
  char* buffer;
  
  uid_t ega_uid;
  gid_t ega_gid;
  char* ega_gecos;         /* EGA User */
  char* ega_shell;         /* /bin/bash or /sbin/nologin */

  double cache_ttl;        /* How long a cache entry is valid (in seconds) */
  char* prompt;            /* Please enter password */

  char* cache_dir;         /* Cache directory for EGA users */

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
  char* ssl_cert;          /* path the SSL certificate to contact Central EGA */
};

typedef struct options_s options_t;

extern options_t* options;

bool loadconfig(void);
void cleanconfig(void);
bool config_not_loaded(void);

static inline void clean_conf(options_t** p){ D3("Cleaning configuration [%p]", *p); cleanconfig(); }
#define _cleanup_conf_ __attribute__((cleanup(clean_conf)))

#endif /* !__LEGA_CONFIG_H_INCLUDED__ */
