#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "utils.h"
#include "config.h"

options_t* options = NULL;

void
cleanconfig(void)
{
  if(!options) return;

  if(options->buffer){ free((char*)options->buffer); }
  free(options);
  return;
}

bool
checkoptions(void)
{
  bool valid = true;
  if(!options) { D("No config struct"); return false; }

  D("Checking the config struct");
  if(!options->prompt            ) { D("Invalid prompt");           valid = false; }

  if(!options->ega_dir           ) { D("Invalid ega_dir");          valid = false; }
  if(!options->ega_dir_attrs     ) { D("Invalid ega_dir_attrs");    valid = false; }
  if(!options->ega_fuse_dir      ) { D("Invalid ega_fuse_dir");     valid = false; }
  if(!options->ega_fuse_flags    ) { D("Invalid ega_fuse_flags");   valid = false; }
  if(!options->ega_fuse_exec     ) { D("Invalid ega_fuse_exec");    valid = false; }

  if(!options->cache_dir         ) { D("Invalid cache_dir");        valid = false; }

  if(!options->ega_uid           ) { D("Invalid ega_uid");          valid = false; }
  if(!options->ega_gid           ) { D("Invalid ega_gid");          valid = false; }
  if(!options->ega_gecos         ) { D("Invalid ega_gecos");        valid = false; }
  if(!options->ega_shell         ) { D("Invalid ega_shell");        valid = false; }

  if(!options->cega_endpoint     ) { D("Invalid cega_endpoint");    valid = false; }
  if(!options->cega_creds        ) { D("Invalid cega_creds");       valid = false; }
  if(!options->cega_json_passwd  ) { D("Invalid cega_json_passwd"); valid = false; }
  if(!options->cega_json_pubkey  ) { D("Invalid cega_json_pubkey"); valid = false; }
  /* if(options->ssl_cert          ) { D("Invalid ssl_cert");      valid = false; } */

  if(!valid) D("Invalid config struct from %s", options->cfgfile);
  return valid;
}

DECLARE_CLEANUP(line);

#define INJECT_OPTION(key,ckey,val,loc) do { if(!strcmp(key, ckey) && copy2buffer(val, &(loc), &buffer, &buflen) < 0 ){ return -1; } } while(0)
#define COPYVAL(val,dest) do { if( copy2buffer(val, &(dest), &buffer, &buflen) < 0 ){ return -1; } } while(0)

static inline int
readconfig(FILE* fp, const char* configfile, char* buffer, size_t buflen)
{
  _cleanup_str_(line) char* line = NULL;
  size_t len = 0;
  char *key,*eq,*val,*end;

  /* Default config values */
  options->expiration = EGA_ACCOUNT_EXPIRATION;
  options->with_cega = ENABLE_CEGA;

  COPYVAL(configfile, options->cfgfile   );
  COPYVAL(CACHE_DIR , options->cache_dir );
  COPYVAL(PROMPT    , options->prompt    );
  COPYVAL(CEGA_CERT , options->ssl_cert  );
  COPYVAL(EGA_GECOS , options->ega_gecos );
  COPYVAL(EGA_SHELL , options->ega_shell );

  /* Parse line by line */
  while (getline(&line, &len, fp) > 0) {
	
    key=line;
    /* remove leading whitespace */
    while(isspace(*key)) key++;
      
    if((eq = strchr(line, '='))) {
      end = eq - 1; /* left of = */
      val = eq + 1; /* right of = */
	  
      /* find the end of the left operand */
      while(end > key && isspace(*end)) end--;
      *(end+1) = '\0';
	  
      /* find where the right operand starts */
      while(*val && isspace(*val)) val++;
	  
      /* find the end of the right operand */
      eq = val;
      while(*eq != '\0') eq++;
      eq--;
      if(*eq == '\n') { *eq = '\0'; } /* remove new line */
	  
    } else val = NULL; /* could not find the '=' sign */
	
    if(!strcmp(key, "debug"             )) { options->debug = true; }

    if(!strcmp(key, "ega_dir_attrs"     )) { options->ega_dir_attrs = strtol(val, NULL, 8);    }
    if(!strcmp(key, "ega_uid"           )) { options->ega_uid = (uid_t) strtol(val, NULL, 10); }
    if(!strcmp(key, "ega_gid"           )) { options->ega_gid = (uid_t) strtol(val, NULL, 10); }
    if(!strcmp(key, "expiration"        )) { options->expiration = strtol(val, NULL, 10); }

    INJECT_OPTION(key, "ega_dir" , val, options->ega_dir);
    INJECT_OPTION(key, "ega_gecos"     , val, options->ega_gecos     );
    INJECT_OPTION(key, "ega_shell"     , val, options->ega_shell     );
    INJECT_OPTION(key, "ega_fuse_dir"  , val, options->ega_fuse_dir  );
    INJECT_OPTION(key, "ega_fuse_exec" , val, options->ega_fuse_exec );
    INJECT_OPTION(key, "ega_fuse_flags", val, options->ega_fuse_flags);

    INJECT_OPTION(key, "cache_dir"     , val, options->cache_dir     );
    INJECT_OPTION(key, "prompt"        , val, options->prompt        );
    
    INJECT_OPTION(key, "cega_endpoint"    , val, options->cega_endpoint    );
    INJECT_OPTION(key, "cega_creds"       , val, options->cega_creds       );
    INJECT_OPTION(key, "cega_json_passwd" , val, options->cega_json_passwd );
    INJECT_OPTION(key, "cega_json_pubkey" , val, options->cega_json_pubkey );
    INJECT_OPTION(key, "ssl_cert"         , val, options->ssl_cert         );

    if(!strcmp(key, "enable_cega")) {
      if(!strcmp(val, "yes") || !strcmp(val, "true")){
	options->with_cega = true;
      } else {
	D("Could not parse the enable_cega: Using %s instead.", ((options->with_cega)?"yes":"no"));
      }
    }	
  }
  return 0;
}

bool
loadconfig(const char* configfile)
{
  D("Loading configuration %s", configfile);
  if(options) return true; /* Done already */

  _cleanup_file_ FILE* fp = NULL;
  size_t size = 1024;
  
  /* read or re-read */
  fp = fopen(configfile, "r");
  if (fp == NULL || errno == EACCES) { SYSLOG("Error accessing the config file: %s", strerror(errno)); return false; }

  options = (options_t*)malloc(sizeof(options_t));
  options->buffer = NULL;

REALLOC:
  /* D("******************* Allocating buffer of size %zd", size); */
  options->buffer = realloc(options->buffer, sizeof(char) * size);

  if( readconfig(fp, configfile, options->buffer, size) < 0 ){
    size = size << 1; // double it
    goto REALLOC;
  }
  
  if(options->debug) return checkoptions();
  return true;
}
