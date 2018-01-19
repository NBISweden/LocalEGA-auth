#include <nss.h>
#include <pwd.h>
#include <string.h>

#include "debug.h"
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
  enum nss_status status = NSS_STATUS_UNAVAIL;

  D("called with args (stayopen: %d)", stayopen);
  
  if(backend_open(stayopen)) {
    status = NSS_STATUS_SUCCESS;
  }

  /* if(!stayopen) backend_close(); */
  return status;
}

enum nss_status
_nss_ega_endpwent(void)
{
  D("called");
  backend_close();
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
  if( !strcmp(username, "root") ){ D("bail out when root"); return NSS_STATUS_NOTFOUND; }
  if( !strcmp(username, "ega")  ){ D("bail out when ega");  return NSS_STATUS_NOTFOUND; }

  D("called with username: %s and initial buffer size: %zd", username, buflen);

  enum nss_status status = NSS_STATUS_NOTFOUND;

  if(!backend_open(0)) return NSS_STATUS_UNAVAIL;

  status = backend_convert(username, result, &buffer, &buflen, errnop);
  if (status == NSS_STATUS_SUCCESS) return status;

  /* OK, User not found in Cache */

  /* if CEGA disabled */
  if(!options->with_cega){
    D("Contacting cega for user %s is disabled", username);
    return NSS_STATUS_NOTFOUND;
  }
    
  int rc = fetch_from_cega(username, &buffer, &buflen, errnop);

  if( rc == -1){ *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
  if( rc ){ D("Fetch CEGA error: %d", rc); return NSS_STATUS_NOTFOUND; }

  /* User retrieved from Central EGA, try again the DB */
  status = backend_convert(username, result, &buffer, &buflen, errnop);
  if (status == NSS_STATUS_SUCCESS){
    create_ega_dir(options->ega_dir, username, result->pw_uid, result->pw_gid, options->ega_dir_attrs); /* In that case, create the homedir */
    return status;
  }

  D("No luck, user %s not found", username);
  /* No luck, user not found */
  return NSS_STATUS_NOTFOUND;
}

/*
 * Finally: No group functions here
 */
