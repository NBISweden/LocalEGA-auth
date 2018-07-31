
#ifndef __LEGA_CONFIG_H_INCLUDED__
#define __LEGA_CONFIG_H_INCLUDED__

#include <stdbool.h>
#include <sys/types.h> 

#define CFGFILE "/etc/ega/auth.conf"
#define CEGA_CERT "/etc/ega/cega.pem"
#define PROMPT "Please, enter your EGA password: "

#define CACHE_TTL 3600.0 // 1h in seconds.
#define EGA_UID_SHIFT 10000
#define EGA_SHELL "/bin/bash"

struct options_s {
  char* cfgfile;
  char* buffer;
  
  gid_t gid;               /* group id for all EGA users */
  uid_t uid_shift;         /* added to the user id from CentralEGA */
  char* prompt;            /* Please enter password */
  char* shell;             /* Please enter password */

  char* db_path;           /* db file path */

  char* ega_dir;           /* EGA main inbox directory */
  long int ega_dir_attrs;  /* in octal form */
  char* ega_fuse_exec;     /* LegaFS fuse executable */
  char* ega_fuse_flags;    /* Mount flags for fuse directory per user */

  /* Contacting Central EGA (vie REST call) */
  char* cega_endpoint_name;   /* https://central_ega/user/<some-name> | returns a triplet in JSON format */
  char* cega_endpoint_uid;    /* https://central_ega/id/<some-id>     | idem                             */
  char* cega_json_prefix;  /* Searching with jq for the user data using this prefix */
  char* cega_creds;        /* for authentication: user:password */
  char* ssl_cert;          /* path the SSL certificate to contact Central EGA */

  char* x; /* internal user */
};

typedef struct options_s options_t;

extern options_t* options;

bool loadconfig(void);
void cleanconfig(void);

#endif /* !__LEGA_CONFIG_H_INCLUDED__ */
