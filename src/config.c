#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "debug.h"
#include "config.h"

options_t* options = NULL;

void
cleanconfig(void)
{
  if(!options) return;

  SYSLOG("Cleaning the config struct");
  if(!options->cfgfile          ) { free((char*)options->cfgfile);        }
  if(options->db_connstr        ) { free((char*)options->db_connstr);     }
  if(options->get_ent           ) { free((char*)options->get_ent);        }
  if(options->add_user          ) { free((char*)options->add_user);       }
  if(options->get_password      ) { free((char*)options->get_password);   }
  if(options->get_account       ) { free((char*)options->get_account);    }
  if(options->prompt            ) { free((char*)options->prompt);         }
  if(options->ega_dir           ) { free((char*)options->ega_dir);        }
  if(options->ega_fuse_dir      ) { free((char*)options->ega_fuse_dir);   }
  if(options->ega_fuse_flags    ) { free((char*)options->ega_fuse_flags); }
  if(options->ega_fuse_exec     ) { free((char*)options->ega_fuse_exec);  }
  if(options->ega_gecos         ) { free((char*)options->ega_gecos);      }
  if(options->ega_shell         ) { free((char*)options->ega_shell);      }
  if(options->cega_endpoint     ) { free((char*)options->cega_endpoint);  }
  if(options->cega_user         ) { free((char*)options->cega_user);      }
  if(options->cega_password     ) { free((char*)options->cega_password);  }
  if(options->cega_resp_passwd  ) { free((char*)options->cega_resp_passwd); }
  if(options->cega_resp_pubkey  ) { free((char*)options->cega_resp_pubkey); }
  if(options->ssl_cert          ) { free((char*)options->ssl_cert);       }
  free(options);
  return;
}

#define INVALID(x) D("Invalid "#x);

bool
checkoptions(void)
{
  bool valid = true;
  if(!options) {
    D("No config struct");
    return false;
  }

  D("Checking the config struct");
  if(!options->db_connstr        ) { INVALID("db_connection");    valid = false; }
  if(!options->get_ent           ) { INVALID("get_ent");          valid = false; }
  if(!options->add_user          ) { INVALID("add_user");         valid = false; }
  if(!options->get_password      ) { INVALID("get_password");     valid = false; }
  if(!options->get_account       ) { INVALID("get_account");      valid = false; }
  if(!options->prompt            ) { INVALID("prompt");           valid = false; }

  if(!options->ega_dir           ) { INVALID("ega_dir");          valid = false; }
  if(!options->ega_dir_attrs     ) { INVALID("ega_dir_attrs");    valid = false; }
  if(!options->ega_fuse_dir      ) { INVALID("ega_fuse_dir");     valid = false; }
  if(!options->ega_fuse_flags    ) { INVALID("ega_fuse_flags");   valid = false; }
  if(!options->ega_fuse_exec     ) { INVALID("ega_fuse_exec");    valid = false; }

  if(!options->ega_uid           ) { INVALID("ega_uid");          valid = false; }
  if(!options->ega_gid           ) { INVALID("ega_gid");          valid = false; }
  if(!options->ega_gecos         ) { INVALID("ega_gecos");        valid = false; }
  if(!options->ega_shell         ) { INVALID("ega_shell");        valid = false; }

  if(!options->cega_endpoint     ) { INVALID("cega_endpoint");    valid = false; }
  if(!options->cega_user         ) { INVALID("cega_user");        valid = false; }
  if(!options->cega_password     ) { INVALID("cega_password");    valid = false; }
  if(!options->cega_resp_passwd  ) { INVALID("cega_resp_passwd"); valid = false; }
  if(!options->cega_resp_pubkey  ) { INVALID("cega_resp_pubkey"); valid = false; }
  /* if(options->ssl_cert          ) { INVALID("ssl_cert");      valid = false; } */

  if(!valid) D("Invalid config struct");
  return valid;
}

bool
readconfig(const char* configfile)
{

  FILE* fp;
  char* line = NULL;
  size_t len = 0;
  char *key,*eq,*val,*end;

  D("called (cfgfile: %s)", configfile);

  if(options) return true; /* Done already */

  SYSLOG("Loading configuration %s", configfile);

  /* read or re-read */
  fp = fopen(configfile, "r");
  if (fp == NULL || errno == EACCES) {
    SYSLOG("Error accessing the config file: %s", strerror(errno));
    cleanconfig();
    return false;
  }
      
  options = (options_t*)malloc(sizeof(options_t));
      
  /* Default config values */
  options->cfgfile = configfile;
  options->with_cega = ENABLE_CEGA;
  options->rest_buffer_size = BUFFER_REST;
  options->prompt = PROMPT;
  options->ssl_cert = CEGA_CERT;

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
	
    if(!strcmp(key, "debug"             )) { options->debug = true;                 }
    if(!strcmp(key, "db_connection"     )) { options->db_connstr = strdup(val);     }

    if(!strcmp(key, "add_user"          )) { options->add_user = strdup(val);       }
    if(!strcmp(key, "ega_dir"           )) { options->ega_dir = strdup(val);        }
    if(!strcmp(key, "ega_dir_attrs"     )) { options->ega_dir_attrs = strtol(val, NULL, 8);    }
    if(!strcmp(key, "ega_uid"           )) { options->ega_uid = (uid_t) strtol(val, NULL, 10); }
    if(!strcmp(key, "ega_gid"           )) { options->ega_gid = (uid_t) strtol(val, NULL, 10); }
    if(!strcmp(key, "ega_gecos"         )) { options->ega_gecos = strdup(val);      }
    if(!strcmp(key, "ega_shell"         )) { options->ega_shell = strdup(val);      }

    if(!strcmp(key, "ega_fuse_dir"      )) { options->ega_fuse_dir = strdup(val);   }
    if(!strcmp(key, "ega_fuse_exec"     )) { options->ega_fuse_exec = strdup(val);  }
    if(!strcmp(key, "ega_fuse_flags"    )) { options->ega_fuse_flags = strdup(val); }

    if(!strcmp(key, "get_ent"           )) { options->get_ent = strdup(val);        }
    if(!strcmp(key, "get_password"      )) { options->get_password = strdup(val);   }
    if(!strcmp(key, "get_account"       )) { options->get_account = strdup(val);    }
    if(!strcmp(key, "prompt"            )) { options->prompt = strdup(val);         }

    if(!strcmp(key, "cega_endpoint"     )) { options->cega_endpoint = strdup(val);  }
    if(!strcmp(key, "cega_user"         )) { options->cega_user     = strdup(val);  }
    if(!strcmp(key, "cega_password"     )) { options->cega_password = strdup(val);  }
    if(!strcmp(key, "cega_resp_passwd"  )) { options->cega_resp_passwd=strdup(val); }
    if(!strcmp(key, "cega_resp_pubkey"  )) { options->cega_resp_pubkey=strdup(val); }
    if(!strcmp(key, "rest_buffer_size"  )) { options->rest_buffer_size=strtol(val, NULL, 10); }
    if(!strcmp(key, "ssl_cert"          )) { options->ssl_cert = strdup(val);       }

    if(!strcmp(key, "enable_cega")) {
      if(!strcmp(val, "yes") || !strcmp(val, "true")){
	options->with_cega = true;
      } else {
	SYSLOG("Could not parse the enable_cega: Using %s instead.", ((options->with_cega)?"yes":"no"));
      }
    }	
  }

  fclose(fp);
  if (line) { free(line); }

  D("options: %p", options);
  if(options->debug) return checkoptions();
  return true;
}
