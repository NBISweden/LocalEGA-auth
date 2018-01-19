#ifndef __LEGA_CONFIG_H_INCLUDED__
#define __LEGA_CONFIG_H_INCLUDED__

#include <stdbool.h>
#include <sys/types.h> 

#define CFGFILE "/etc/ega/auth.conf"
#define ENABLE_CEGA false
#define CEGA_CERT "/etc/ega/cega.pem"
#define PROMPT "Please, enter your EGA password: "
#define EGA_ACCOUNT_EXPIRATION 100

#define CACHE_DIR "/ega/cache"
#define STORAGE_SIZE 1024
#define PASSWORD "/password_hash"
#define PUBKEY   "/pubkey"

struct options_s {
  bool debug;
  const char* cfgfile;
  
  /* Database cache connection */
  char* db_connstr;

  /* NSS & PAM queries */
  uid_t ega_uid;
  gid_t ega_gid;
  const char* ega_gecos;      /* EGA User */
  const char* ega_shell;      /* /bin/bash or /sbin/nologin */

  long int expiration;        /* Delay in minutes */
  const char* prompt;         /* Please enter password */

  const char* cache_dir;      /* Cache directory for EGA users */

  const char* ega_dir;        /* EGA main inbox directory */
  long int ega_dir_attrs;     /* in octal form */
  const char* ega_fuse_dir;   /* EGA virtual fuse top directory */
  const char* ega_fuse_exec;  /* LegaFS fuse executable */
  char* ega_fuse_flags;       /* Mount flags for fuse directory per user */

  /* Contacting Central EGA (vie REST call) */
  bool with_cega;                /* enable the lookup in case the entry is not found in the database cache */
  const char* cega_endpoint;     /* https://central_ega/user/<some-id> | returns a triplet in JSON format */
  const char* cega_user;      
  const char* cega_password;     /* for authentication: user:password */
  const char* cega_resp_passwd;  /* Searching with jq for the password field */
  const char* cega_resp_pubkey;  /* Searching with jq for the public key field */
  const char* ssl_cert;          /* path the SSL certificate to contact Central EGA */
};

typedef struct options_s options_t;

extern options_t* options;

bool readconfig(const char* configfile);
void cleanconfig(void);
    
#endif /* !__LEGA_CONFIG_H_INCLUDED__ */
