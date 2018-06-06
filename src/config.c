#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "utils.h"
#include "config.h"

options_t* options = NULL;

bool config_not_loaded(void) { return options == NULL; }

void
cleanconfig(void)
{
  if(!options) return;
  D2("Cleaning configuration [%p]", options);

  if(options->buffer){ free((char*)options->buffer); }
  free(options);
  return;
}


bool
checkoptions(void)
{
  bool valid = true;
  if(!options) { D3("No config struct"); return false; }

  D2("Checking the config struct");
  if(options->cache_ttl < 0.0    ) { D3("Invalid cache_ttl");        valid = false; }
  if(options->ega_uid < 0        ) { D3("Invalid ega_uid");          valid = false; }
  if(options->ega_gid < 0        ) { D3("Invalid ega_gid");          valid = false; }

  if(!options->prompt            ) { D3("Invalid prompt");           valid = false; }

  if(!options->ega_dir           ) { D3("Invalid ega_dir");          valid = false; }
  if(!options->ega_dir_attrs     ) { D3("Invalid ega_dir_attrs");    valid = false; }
  if(!options->ega_fuse_flags    ) { D3("Invalid ega_fuse_flags");   valid = false; }
  if(!options->ega_fuse_exec     ) { D3("Invalid ega_fuse_exec");    valid = false; }

  if(!options->cache_dir         ) { D3("Invalid cache_dir");        valid = false; }

  if(!options->ega_uid           ) { D3("Invalid ega_uid");          valid = false; }
  if(!options->ega_gid           ) { D3("Invalid ega_gid");          valid = false; }
  if(!options->ega_gecos         ) { D3("Invalid ega_gecos");        valid = false; }
  if(!options->ega_shell         ) { D3("Invalid ega_shell");        valid = false; }

  if(!options->cega_endpoint     ) { D3("Invalid cega_endpoint");    valid = false; }
  if(!options->cega_creds        ) { D3("Invalid cega_creds");       valid = false; }
  if(!options->cega_json_passwd  ) { D3("Invalid cega_json_passwd"); valid = false; }
  if(!options->cega_json_pubkey  ) { D3("Invalid cega_json_pubkey"); valid = false; }
  /* if(options->ssl_cert          ) { D3("Invalid ssl_cert");      valid = false; } */

  if(!valid){ D3("Invalid config struct from %s", options->cfgfile); }
  return valid;
}

#define INJECT_OPTION(key,ckey,val,loc) do { if(!strcmp(key, ckey) && copy2buffer(val, &(loc), &buffer, &buflen) < 0 ){ return -1; } } while(0)
#define COPYVAL(val,dest) do { if( copy2buffer(val, &(dest), &buffer, &buflen) < 0 ){ return -1; } } while(0)

static inline int
readconfig(FILE* fp, char* buffer, size_t buflen)
{
  _cleanup_str_ char* line = NULL;
  size_t len = 0;
  char *key,*eq,*val,*end;

  /* Default config values */
  options->cache_ttl = CACHE_TTL;
  options->with_cega = ENABLE_CEGA;

  COPYVAL(CFGFILE   , options->cfgfile   );
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
	
    if(!strcmp(key, "ega_dir_attrs"     )) { options->ega_dir_attrs = strtol(val, NULL, 8);    }
    if(!strcmp(key, "ega_uid"           )) { if( !sscanf(val, "%u" , &(options->ega_uid)   )) options->ega_uid = -1; }
    if(!strcmp(key, "ega_gid"           )) { if( !sscanf(val, "%u" , &(options->ega_gid)   )) options->ega_gid = -1; }
    if(!strcmp(key, "cache_ttl"         )) { if( !sscanf(val, "%lf", &(options->cache_ttl) )) options->cache_ttl = -1; }

    INJECT_OPTION(key, "ega_dir" , val, options->ega_dir);
    INJECT_OPTION(key, "ega_gecos"     , val, options->ega_gecos     );
    INJECT_OPTION(key, "ega_shell"     , val, options->ega_shell     );
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
	D2("Could not parse the enable_cega: Using %s instead.", ((options->with_cega)?"yes":"no"));
      }
    }	
  }
  return 0;
}

bool
loadconfig(void)
{
  D2("Loading configuration %s", CFGFILE);
  if(options){ D2("Already loaded [@ %p]", options); return true; }

  _cleanup_file_ FILE* fp = NULL;
  size_t size = 1024;
  
  /* read or re-read */
  fp = fopen(CFGFILE, "r");
  if (fp == NULL || errno == EACCES) { D2("Error accessing the config file: %s", strerror(errno)); return false; }

  options = (options_t*)malloc(sizeof(options_t));
  if(!options){ D3("Could not allocate options data structure"); return false; };
  options->buffer = NULL;

REALLOC:
  D3("Allocating buffer of size %zd", size);
  if(options->buffer)free(options->buffer);
  options->buffer = malloc(sizeof(char) * size);
  if(!options->buffer){ D3("Could not allocate buffer of size %zd", size); return false; };

  if( readconfig(fp, options->buffer, size) < 0 ){
    size = size << 1; // double it
    goto REALLOC;
  }

  D2("Conf loaded [@ %p]", options);

#ifdef DEBUG
  return checkoptions();
#else
  return true;
#endif
}


/*
 * Constructor/Destructor when the library is loaded
 *
 * See: http://man7.org/linux/man-pages/man3/dlopen.3.html
 *
 */
__attribute__((constructor))
static void initconfig(void){ D3("********** CONSTRUCTOR"); loadconfig(); }

__attribute__((destructor))
static void destroyconfig(void){ D3("********** DESTRUCTOR"); cleanconfig(); }
