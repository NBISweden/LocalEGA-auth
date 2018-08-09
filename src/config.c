#include <ctype.h>
#include <errno.h>
#include <grp.h>

#include "utils.h"
#include "config.h"

options_t* options = NULL;

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
valid_options(void)
{
  bool valid = true;
  if(!options) { D3("No config struct"); return false; }

  D2("Checking the config struct");
  if(options->cache_ttl < 0.0    ) { D3("Invalid cache_ttl");        valid = false; }
  if(options->uid_shift < 0      ) { D3("Invalid ega_uid_shift");    valid = false; }
  if(options->gid < 0            ) { D3("Invalid ega_gid");          valid = false; }

  if(!options->shell             ) { D3("Invalid shell");            valid = false; }
  if(!options->prompt            ) { D3("Invalid prompt");           valid = false; }

  if(!options->ega_dir           ) { D3("Invalid ega_dir");          valid = false; }
  if(!options->ega_dir_attrs     ) { D3("Invalid ega_dir_attrs");    valid = false; }
  if(!options->ega_dir_umask     ) { D3("Invalid ega_dir_umask");    valid = false; }

  if(!options->db_path           ) { D3("Invalid db_path");          valid = false; }

  if(!options->cega_creds        ) { D3("Invalid cega_creds");       valid = false; }
  if(!options->cega_endpoint_name) { D3("Invalid cega_endpoint for usernames");    valid = false; }
  if(!options->cega_endpoint_uid ) { D3("Invalid cega_endpoint for user ids");    valid = false; }

  /* if(options->ssl_cert          ) { D3("Invalid ssl_cert");      valid = false; } */

  if(!valid){ D3("Invalid config struct from %s", options->cfgfile); }
  return valid;
}

#define INJECT_OPTION(key,ckey,val,loc) do { if(!strcmp(key, ckey) && copy2buffer(val, &(loc), &buffer, &buflen) < 0 ){ return -1; } } while(0)
#define COPYVAL(val,dest) do { if( copy2buffer(val, &(dest), &buffer, &buflen) < 0 ){ return -1; } } while(0)

static inline int
readconfig(FILE* fp, char* buffer, size_t buflen)
{
  D3("Reading configuration file");
  _cleanup_str_ char* line = NULL;
  size_t len = 0;
  char *key,*eq,*val,*end;

  /* Default config values */
  options->uid_shift = EGA_UID_SHIFT;
  options->gid = -1;
  options->chroot = ENABLE_CHROOT;
  options->ega_dir_umask = (mode_t)UMASK;
  options->cache_ttl = CACHE_TTL;

  COPYVAL(CFGFILE   , options->cfgfile          );
  COPYVAL(PROMPT    , options->prompt           );
  COPYVAL(CEGA_CERT , options->ssl_cert         );
  COPYVAL(EGA_SHELL , options->shell            );
  COPYVAL(""        , options->cega_json_prefix ); /* default */
  COPYVAL("x"       , options->x ); /* internal use */

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
	
    if(!strcmp(key, "ega_dir_umask" )) { options->ega_dir_umask = strtol(val, NULL, 8); } /* ok when val contains a comment #... */
    if(!strcmp(key, "ega_dir_attrs" )) { options->ega_dir_attrs = strtol(val, NULL, 8); }
    if(!strcmp(key, "ega_uid_shift" )) { if( !sscanf(val, "%u" , &(options->uid_shift) )) options->uid_shift = -1; }
    if(!strcmp(key, "cache_ttl"     )) { if( !sscanf(val, "%u" , &(options->cache_ttl) )) options->cache_ttl = -1; }
    if(!strcmp(key, "ega_gid"       )) { if( !sscanf(val, "%u" , &(options->gid)   )) options->gid = -1; }
   
    INJECT_OPTION(key, "db_path"           , val, options->db_path          );
    INJECT_OPTION(key, "ega_dir"           , val, options->ega_dir          );
    INJECT_OPTION(key, "prompt"            , val, options->prompt           );
    INJECT_OPTION(key, "ega_shell"         , val, options->shell            );
    INJECT_OPTION(key, "cega_endpoint_name", val, options->cega_endpoint_name);
    INJECT_OPTION(key, "cega_endpoint_uid" , val, options->cega_endpoint_uid);
    INJECT_OPTION(key, "cega_creds"        , val, options->cega_creds       );
    INJECT_OPTION(key, "cega_json_prefix"  , val, options->cega_json_prefix );
    INJECT_OPTION(key, "ssl_cert"          , val, options->ssl_cert         );


    if(!strcmp(key, "chroot_isolation")) {
      if(!strcmp(val, "yes") || !strcmp(val, "true") || !strcmp(val, "1") || !strcmp(val, "on")){
	options->chroot = true;
      } else if(!strcmp(val, "no") || !strcmp(val, "false") || !strcmp(val, "0") || !strcmp(val, "off")){
	options->chroot = false;
      } else {
	D2("Could not parse the chroot_isolation: Using %s instead.", ((options->chroot)?"yes":"no"));
      }
    }	
  }

  return 0;
}

bool
loadconfig(void)
{
  D1("Loading configuration %s", CFGFILE);
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
  /* memset(options->buffer, '\0', size); */
  *(options->buffer) = '\0';
  if(!options->buffer){ D3("Could not allocate buffer of size %zd", size); return false; };

  if( readconfig(fp, options->buffer, size) < 0 ){
    size = size << 1; // double it
    goto REALLOC;
  }

  D2("Conf loaded [@ %p]", options);

#ifdef DEBUG
  return valid_options();
#else
  return true;
#endif
}
