#include <nss.h>
#include <pwd.h>
#include <errno.h>
#include <sys/stat.h>

#include "utils.h"
#include "backend.h"
#include "cega.h"
#include "homedir.h"


/*
 * passwd functions
 */

/* Not allowed */
enum nss_status _nss_ega_setpwent (int stayopen){ D1("called"); return NSS_STATUS_UNAVAIL; }
enum nss_status _nss_ega_endpwent(void){ D1("called"); return NSS_STATUS_UNAVAIL; }
enum nss_status _nss_ega_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop){ D1("called"); return NSS_STATUS_UNAVAIL; }

enum nss_status
_nss_ega_getpwuid_r(uid_t uid, struct passwd *result,
		    char *buffer, size_t buflen, int *errnop)
{
  /* bail out if we're looking for the root user */
  /* if( !strcmp(username, "root") ){ D1("bail out when root"); return NSS_STATUS_NOTFOUND; } */

  D1("Looking up user id %d", uid);

  if( !backend_opened() ) return NSS_STATUS_UNAVAIL;

  D3("initial buffer size: %zd", buflen);
  /* memset(buffer, '\0', buflen); */

  int rc = backend_getpwuid_r(uid, result, buffer, buflen);
  if( rc == -1 ){ D1("Buffer too small"); *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
  if( rc == 0 ){ D1("User found in cache"); *errnop = 0; return NSS_STATUS_SUCCESS; }

  D1("User id %d not found", uid);
  return NSS_STATUS_NOTFOUND;
}

/* Find user ny name */
enum nss_status
_nss_ega_getpwnam_r(const char *username, struct passwd *result,
		    char *buffer, size_t buflen, int *errnop)
{
  /* bail out if we're looking for the root user */
  /* if( !strcmp(username, "root") ){ D1("bail out when root"); return NSS_STATUS_NOTFOUND; } */

  D1("Looking up '%s'", username);
  /* memset(buffer, '\0', buflen); */

  bool use_backend = backend_opened();
  int rc = 1;
  if(use_backend){
    
    rc = backend_getpwnam_r(username, result, buffer, buflen);
    if( rc == -1 ){ D1("Buffer too small"); *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
    if( rc == 0  ){ REPORT("User %s found in cache", username); *errnop = 0; return NSS_STATUS_SUCCESS; }
    
  }

  if(!options->with_cega){ D1("Contacting CentralEGA is disabled"); return NSS_STATUS_UNAVAIL; }

  /* Defining the callback */
  int cega_callback(uid_t uid, char* password_hash, char* pubkey, char* gecos){

    /* Add to database. Ignore result.
     In case the buffer is too small later, it'll fetch the same data from the cache, next time. */
    if(use_backend) backend_add_user(username, uid, password_hash, pubkey, gecos);

    /* Prepare the answer */
    char* homedir = strjoina(options->ega_dir, "/", username);
    D3("Username %s [%s]", username, homedir);
    result->pw_name = (char*)username; /* no need to copy to buffer */
    result->pw_passwd = options->x;
    result->pw_uid = uid;
    result->pw_gid = options->gid;
    if( copy2buffer(homedir, &(result->pw_dir)   , &buffer, &buflen) < 0 ) { return -1; }
    if( copy2buffer(gecos,   &(result->pw_gecos) , &buffer, &buflen) < 0 ) { return -1; }
    if( copy2buffer(options->shell, &(result->pw_shell), &buffer, &buflen) < 0 ) { return -1; }
  
    /* make sure the homedir is created */
    create_ega_dir(result); // ignore output, in nss case
    return 0;
  }

  rc = cega_get_username(username, cega_callback);
  if( rc == -1 ){ D1("Buffer too small"); *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
  if( rc > 0 ) { D1("User %s not found in CentralEGA", username); return NSS_STATUS_NOTFOUND; }
  REPORT("User %s found in CentralEGA", username);
  *errnop = 0;
  return NSS_STATUS_SUCCESS;
}

/*
 * Finally: No group functions here
 */
