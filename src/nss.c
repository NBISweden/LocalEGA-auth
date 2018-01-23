#include <nss.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>

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
  D1("called");
  return NSS_STATUS_UNAVAIL;
}

enum nss_status
_nss_ega_endpwent(void)
{
  D1("called");
  return NSS_STATUS_UNAVAIL;
}

/* Not allowed */
enum nss_status
_nss_ega_getpwent_r(struct passwd *result,
		    char *buffer, size_t buflen,
		    int *errnop)
{
  D1("called");
  return NSS_STATUS_UNAVAIL;
}

/* Find user ny name */
enum nss_status
_nss_ega_getpwnam_r(const char *username, struct passwd *result,
		    char *buffer, size_t buflen, int *errnop)
{
  /* bail out if we're looking for the root user */
  /* if( !strcmp(username, "root") ){ D1("bail out when root"); return NSS_STATUS_NOTFOUND; } */
  /* if( !strcmp(username, "ega")  ){ D1("bail out when ega");  return NSS_STATUS_NOTFOUND; } */

  D1("Looking up '%s'", username);

  if( config_not_loaded() ) return NSS_STATUS_UNAVAIL;

  D3("initial buffer size: %zd", buflen);

  switch(backend_convert(username, result, buffer, buflen)){
  case -1:
    *errnop = ERANGE; return NSS_STATUS_TRYAGAIN;
    break;
  case 0: /* User found in cache */
    *errnop = 0; return NSS_STATUS_SUCCESS;
    break; 
  default: /* User not found in cache */
    D1("User not found in cache");
    break; 
  }

  /* Contacting CentralEGA */
  if( !fetch_from_cega(username) ){ D1("Could not fetch user from CentralEGA"); return NSS_STATUS_NOTFOUND; }

  D1("Trying cache again");

  /* User retrieved from Central EGA, try again the cache */
  switch(backend_convert(username, result, buffer, buflen)){
  case -1:
    *errnop = ERANGE; return NSS_STATUS_TRYAGAIN;
    break;
  case 0:
    *errnop = 0;
    return create_ega_dir(options->ega_dir, username, result->pw_uid, result->pw_gid, options->ega_dir_attrs)?NSS_STATUS_SUCCESS:NSS_STATUS_NOTFOUND;
    break;
  default:
    D1("No luck, user %s not found", username);
    return NSS_STATUS_NOTFOUND;
    break;
  }
}

/*
 * Finally: No group functions here
 */
