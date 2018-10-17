
#ifndef __LEGA_CONFIG_H_INCLUDED__
#define __LEGA_CONFIG_H_INCLUDED__

#include <stdbool.h>
#include <sys/types.h> 

struct options_s {
  char* cfgfile;
  char* buffer;
  
  gid_t gid;               /* group id for all EGA users */
  uid_t uid_shift;         /* added to the user id from CentralEGA */
  char* prompt;            /* Please enter password */
  char* shell;             /* Please enter password */
  unsigned int cache_ttl;  /* How long a cache entry is valid (in seconds) */

  char* db_path;           /* db file path */

  /* Homedir */
  char* ega_dir;           /* EGA main inbox directory */
  long int ega_dir_attrs;  /* in octal form */
  mode_t ega_dir_umask;    /* user process's mask */
  bool chroot;             /* sandboxing the users in their home directory */

  /* Contacting Central EGA (vie REST call) */
  char* cega_endpoint_username; /* string format with one %s, replaced by username | returns a triplet in JSON format */
  size_t cega_endpoint_username_len; /* its length, -2 (for %s) */

  char* cega_endpoint_uid;      /* string format with one %s, replaced by uid      | idem */
  size_t cega_endpoint_uid_len; /* its length, -2 (for %s) */

  char* cega_json_prefix;  /* Searching for the data rooted at this prefix */

  char* cega_creds;        /* for authentication: user:password */
  char* ssl_cert;          /* path the SSL certificate to contact Central EGA */
};

typedef struct options_s options_t;

extern options_t* options;

bool loadconfig(void);
void cleanconfig(void);

#endif /* !__LEGA_CONFIG_H_INCLUDED__ */
