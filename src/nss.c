#include <nss.h>
#include <pwd.h>
#include <string.h>

#include "utils.h"
#include "config.h"
#include "backend.h"
#include "cega.h"
#include "homedir.h"


/*
 * passwd functions
 */
enum nss_status
_nss_ega_setpwent (int stayopen)
{
  D("stayopen: %d", stayopen);

  if(!loadconfig(CFGFILE)){ D("Can't read config"); return NSS_STATUS_UNAVAIL; }

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_ega_endpwent(void)
{
  D("success");
  cleanconfig();
  return NSS_STATUS_SUCCESS;
}

/* Not allowed */
enum nss_status
_nss_ega_getpwent_r(struct passwd *result,
		    char *buffer, size_t buflen,
		    int *errnop)
{
  D("called");
  return NSS_STATUS_UNAVAIL;
}

/* Find user ny name */
enum nss_status
_nss_ega_getpwnam_r(const char *username, struct passwd *result,
		    char *buffer, size_t buflen, int *errnop)
{
  /* bail out if we're looking for the root user */
  /* if( !strcmp(username, "root") ){ D("bail out when root"); return NSS_STATUS_NOTFOUND; } */
  /* if( !strcmp(username, "ega")  ){ D("bail out when ega");  return NSS_STATUS_NOTFOUND; } */

  D("called with username: %s and initial buffer size: %zd", username, buflen);

  _cleanup_conf_ char* config_file = CFGFILE;
  if(!loadconfig(config_file)){ D("Can't read config"); return NSS_STATUS_UNAVAIL; }

  switch(backend_convert(username, result, buffer, buflen)){
  case -1:
    *errnop = ERANGE; return NSS_STATUS_TRYAGAIN;
    break;
  case 0: /* User found in cache */
    *errnop = 0; return NSS_STATUS_SUCCESS; 
    break; 
  default: /* User not found in cache */
    D("User not found in cache");
    break; 
  }

  /* if CEGA disabled */
  if(!options->with_cega){ D("Contacting cega for user %s is disabled", username); return NSS_STATUS_NOTFOUND; }
    
  if( !fetch_from_cega(username) ){ D("Could not fetch user from CentralEGA"); return NSS_STATUS_NOTFOUND; }

  D("Trying cache again");

  /* User retrieved from Central EGA, try again the cache */
  switch(backend_convert(username, result, buffer, buflen)){
  case -1:
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
    break;
  case 0:
    *errnop = 0;
    return create_ega_dir(options->ega_dir, username, result->pw_uid, result->pw_gid, options->ega_dir_attrs)?NSS_STATUS_SUCCESS:NSS_STATUS_NOTFOUND;
    break;
  default:
    D("No luck, user %s not found", username);
    return NSS_STATUS_NOTFOUND;
    break;
  }
}

/*
 * Finally: No group functions here
 */
