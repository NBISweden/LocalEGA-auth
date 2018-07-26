#include <nss.h>
#include <pwd.h>
#include <errno.h>

#include "utils.h"
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
_nss_ega_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
  D1("called");
  return NSS_STATUS_UNAVAIL;
}

enum nss_status
_nss_ega_getpwuid_r(uid_t uid, struct passwd *result,
		    char *buffer, size_t buflen, int *errnop)
{
  /* bail out if we're looking for the root user */
  /* if( !strcmp(username, "root") ){ D1("bail out when root"); return NSS_STATUS_NOTFOUND; } */
  /* if( !strcmp(username, "ega")  ){ D1("bail out when ega");  return NSS_STATUS_NOTFOUND; } */

  D1("Looking up user id %d", uid);

  if( !backend_opened() ) return NSS_STATUS_UNAVAIL;

  D3("initial buffer size: %zd", buflen);
  /* memset(buffer, '\0', buflen); */

  switch(backend_getpwuid_r(uid, result, buffer, buflen)){
  case -1:
    *errnop = ERANGE; return NSS_STATUS_TRYAGAIN;
    break;
  case 0: /* User found in cache */
    D1("User found in cache");
    *errnop = 0; return NSS_STATUS_SUCCESS;
    break; 
  default: /* User not found in cache */
    D1("User not found in cache");
    break; 
  }

  D1("No luck, user id %d not found", uid);
  return NSS_STATUS_NOTFOUND;
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

  if( !backend_opened() ) return NSS_STATUS_UNAVAIL;

  D3("initial buffer size: %zd", buflen);
  /* memset(buffer, '\0', buflen); */

  switch(backend_getpwnam_r(username, result, buffer, buflen)){
  case -1:
    *errnop = ERANGE; return NSS_STATUS_TRYAGAIN;
    break;
  case 0: /* User found in cache */
    D1("User found in cache");
    *errnop = 0; return NSS_STATUS_SUCCESS;
    break; 
  default: /* User not found in cache */
    D1("User not found in cache");
    break; 
  }

  /* Contacting CentralEGA */
  *errnop = 0;
  int rc = fetch_from_cega(username, result, buffer, buflen);

  if(rc == -1){ *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  if( rc == 0 ){
    bool dir_present = create_ega_dir(result, options->ega_dir_attrs);
    if( dir_present ){
      D1("Success! User %s found", username);
      *errnop = 0; return NSS_STATUS_SUCCESS;
    }
    return NSS_STATUS_NOTFOUND;
  }
  
  D1("Could not fetch user %s from CentralEGA", username);
  return NSS_STATUS_NOTFOUND;
}

/*
 * Finally: No group functions here
 */
