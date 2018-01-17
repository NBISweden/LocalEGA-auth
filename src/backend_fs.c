#define _XOPEN_SOURCE 500
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <crypt.h>
#include <sys/stat.h>
#include <ftw.h>
#include <unistd.h>

#include "debug.h"
#include "config.h"
#include "backend.h"
#include "cega.h"
#include "homedir.h"
#include "blowfish/ow-crypt.h"


bool
backend_open(int stayopen)
{
  D("called with args: stayopen: %d", stayopen);
  if(!readconfig(CFGFILE)){ D("Can't read config"); return false; }

  return true;
}

void
backend_close(void)
{ 
  D("called");
}

/*
  We use 'buffer' to store the cache/username/item path.
  That way, we don't need to allocate strings

  We use 0 for success
        -1 for buffer too small
	-2 for errors in general
	 n strictly positive for nb of bytes returned
*/

static int
_copy2buffer(const char* data, char **bufptr, size_t *buflen)
{
  size_t slen = strlen(data);

  if(*buflen < slen+1) {
    D("buffer too small [currently: %zd] to copy %s [%zd]", *buflen, data, slen);
    return -1;
  }

  strncpy(*bufptr, data, slen);
  (*bufptr)[slen] = '\0';

  *bufptr += slen + 1;
  *buflen -= slen + 1;
  
  return 0;
}

/*
 * Copies <cache_dir>/<username>[/item] to the buffer pointed by bufptr
 */
static int
name2path(const char* username, const char* item, const char** path, char **bufptr, size_t *buflen){
  int rc = 0;

  D("user: %s, item: %s", username, item);
  *path = *bufptr; /* record start */
  
  if( (rc = _copy2buffer(options->cache_dir, bufptr, buflen)) ) { return rc; }
  *(*bufptr-1) = '/'; /* backtrack one char */

  if( (rc = _copy2buffer(username, bufptr, buflen)) ) { return rc; }

  if(item){
    (*bufptr)--; /* backtrack one char */
    if( (rc = _copy2buffer(item, bufptr, buflen)) ) { return rc; }
  }
  return 0;
}

static int
load_file(const char* username, const char* item, char** content, char** bufptr, size_t* buflen){

  long length;
  FILE* f = NULL;
  const char* path = NULL;
  int rc = 0;

  D("Loading %s file for user %s", item, username);

  if( (rc = name2path(username, item, &path, bufptr, buflen)) ){ return rc; }

  f = fopen (path, "rb");
  if(!f){ D("Could not open file: %s", path); return -2; }

  /* Get the size */
  fseek (f, 0, SEEK_END);
  length = ftell(f);
  fseek (f, 0, SEEK_SET); // rewind

  if(*buflen < length + 1) { D("buffer too small for file: %s", path); return -1; }

  *content = *bufptr; /* record where in the buffer */
  rc = fread(*bufptr, sizeof(char), length, f); // \0 terminated?
  *bufptr += length; // +1 ?
  *buflen -= length; // +1 ?

  fclose (f);
  return rc;
}

static int
store_file(const char* username, const char* item, const char* content, char** bufptr, size_t* buflen){

  FILE* f = NULL;
  const char* path = NULL;
  int rc = 0;

  if(!content){ D("Nothing to store for %s", item); return 0; }

  if( (rc = name2path(username, item, &path, bufptr, buflen)) ){ return rc; }

  D("Opening file: %s", path);

  f = fopen (path, "wb");
  if(!f){ D("Could not open file: %s", path); return -2; }
  chmod(path, 0600);

  D("Storing data: %s", content);
  rc = fwrite(content, sizeof(char), strlen(content), f);

  fclose (f);
  return rc;
}

static int
delete_cache(const char *path, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
  D("Deleting %s", path);
  int rv = remove(path);
  if (rv) perror(path);
  return rv;
}

static int
cache_hit(const char* username, const char** path, char **buffer, size_t *buflen){

  struct stat st;
  int rc = -2;

  if( (rc = name2path(username, NULL, path, buffer, buflen)) ) { return rc; }

  D("Path to %s: %s", username, *path);

  /* Check path exists */
  if( stat(*path,&st) ){ 
    if (errno != ENOENT){ D("stat(%s) failed", *path); }
    nftw(*path, delete_cache, 1, FTW_PHYS); /* Delete cache entry */
    return -2;
  }

  /* Check if path is a directory and is -rwx  */
  if( !S_ISDIR(st.st_mode) ){
    D("%s is not a directory", *path);
    nftw(*path, delete_cache, 1, FTW_PHYS); /* Delete cache entry */
    return -2;
  }
  if( (st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != S_IRWXU ){
    D("%s is not 700", *path);
    nftw(*path, delete_cache, 1, FTW_DEPTH | FTW_PHYS); /* Delete cache entry */
    return -2;
  }

  D("%s is a dir and 700", *path);
  return 0;
}


/*
 * 'convert' to struct passwd
 */
static enum nss_status
_get(const char* username, struct passwd *result, char **buffer, size_t *buflen, int *errnop)
{

  const char* path = NULL;
  switch( cache_hit(username, &path, buffer, buflen) ){
  case -1: 
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
    break;
  case -2:
    D("User not found in cache");
    return NSS_STATUS_NOTFOUND;
    break;
  default:
    break;
  }

  /* ok, cache found */
  D("Convert to passwd struct (%s)", path);

  result->pw_name = *buffer;
  if(_copy2buffer(username, buffer, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  result->pw_passwd = *buffer;
  if(_copy2buffer("x", buffer, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  result->pw_gecos = *buffer;
  if(_copy2buffer(options->ega_gecos, buffer, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  result->pw_shell = *buffer;
  if(_copy2buffer(options->ega_shell, buffer, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  result->pw_uid = options->ega_uid;
  result->pw_gid = options->ega_gid;

  /* For the homedir: ega_fuse_dir/username */
  result->pw_dir = *buffer;
  if(_copy2buffer(options->ega_fuse_dir, buffer, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
  *(*buffer-1) = '/'; /* backtrack one char */
  if(_copy2buffer(username, buffer, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  D("Found: %s", username);
  return NSS_STATUS_SUCCESS;
}

/*
 * refresh the user last accessed date
 */
int
backend_refresh_user(const char* username)
{
  D("Not implemented");
  return PAM_SUCCESS;
  /* int status = PAM_SESSION_ERR; */

  /* if(!backend_open(0)) return PAM_SESSION_ERR; */

  /* D("Refreshing user %s", username); */
  /* status = PAM_SUCCESS; */
  /* backend_close(); */
  /* return status; */
}

/*
 * Has the account expired
 */
int
backend_account_valid(const char* username)
{
  D("Not implemented");
  return PAM_SUCCESS;

  /* int status = PAM_PERM_DENIED; */
  /* const char* params[1] = { username }; */
  /* PGresult *res; */

  /* if(!backend_open(0)) return PAM_PERM_DENIED; */

  /* D("Prepared Statement: %s with %s", options->get_account, username); */
  /* res = PQexecParams(conn, options->get_account, 1, NULL, params, NULL, NULL, 0); */

  /* /\* Check answer *\/ */
  /* status = (PQresultStatus(res) == PGRES_TUPLES_OK)?PAM_SUCCESS:PAM_ACCT_EXPIRED; */

  /* backend_close(); */
  /* return status; */
}

/* Assumes backend is open */
int
backend_add_user(const char* username, const char* pwdh, const char* pubkey,
		 char **buffer, size_t *buflen)
{
  int rc = 0;
  const char* userdir = NULL;

  D("pwdh: %s", pwdh);
  D("pbk: %s", pubkey);

  if( !(rc = cache_hit(username, &userdir, buffer, buflen)) ){ return rc; }

  /* Create the new directory */
  if (mkdir(userdir, 0700)){
    D("unable to mkdir 700 %s [%s]", userdir, strerror(errno));
    return false;
  }

  if( (rc = store_file(username, PASSWORD, pwdh, buffer, buflen)) < 0){ D("Problem storing password hash for user %s", username); return rc; }
  if( (rc = store_file(username, PUBKEY, pubkey, buffer, buflen)) < 0){ D("Problem storing public key for user %s", username); return rc; }

  return 0;
}


/*
 * Get one entry from the Postgres result
 * or contact CentralEGA and retry.
 */
enum nss_status
backend_get_userentry(const char *username, struct passwd *result,
		      char **buffer, size_t *buflen, int *errnop)
{
  D("called");
  enum nss_status status = NSS_STATUS_NOTFOUND;

  if(!backend_open(0)) return NSS_STATUS_UNAVAIL;

  status = _get(username, result, buffer, buflen, errnop);
  if (status == NSS_STATUS_SUCCESS) return status;

  /* OK, User not found in Cache */

  /* if CEGA disabled */
  if(!options->with_cega){
    D("Contacting cega for user %s is disabled", username);
    return NSS_STATUS_NOTFOUND;
  }
    
  int rc = fetch_from_cega(username, buffer, buflen, errnop);

  if( rc == -1){ *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
  if( rc ){ D("Fetch CEGA error: %d", rc); return NSS_STATUS_NOTFOUND; }

  /* User retrieved from Central EGA, try again the DB */
  status = _get(username, result, buffer, buflen, errnop);
  if (status == NSS_STATUS_SUCCESS){
    create_ega_dir(options->ega_dir, username, result->pw_uid, result->pw_gid, options->ega_dir_attrs); /* In that case, create the homedir */
    return status;
  }

  D("No luck, user %s not found", username);
  /* No luck, user not found */
  return NSS_STATUS_NOTFOUND;
}


bool
backend_authenticate(const char *username, const char *password)
{
  int rc = 1;
  char* pwdh = NULL;

  size_t storage_size = STORAGE_SIZE;
  char* storage = (char*)malloc( storage_size * sizeof(char) );
  size_t buflen;
  char* buffer;

  if(!storage){ D("Could not allocate a buffer of size %zd", storage_size); rc = -2; goto BAILOUT; }

  if(!backend_open(0)) return false;

INIT:
  buflen = storage_size;
  buffer = storage; /* copy */

  switch( load_file(username, PASSWORD, &pwdh, &buffer, &buflen)) {
  case -1:
    D("Resizing to %zd", storage_size);
    storage_size *= 2;
    D("Resizing to %zd", storage_size);
    if(!realloc(storage, storage_size * sizeof(char))){ D("Could not resize the internal storage"); return false; }
    goto INIT;
    break;
  case -2:
    D("Error with password_hash file for user %s", username);
    goto BAILOUT;
    break;
  default:
    if(!pwdh){ D("could not load the password_hash for user %s", username); goto BAILOUT; }
    break;
  }

  // all good

  if(!strncmp(pwdh, "$2", 2)){
    D("Using Blowfish");
    char pwdh_computed[64];
    if( crypt_rn(password, pwdh, pwdh_computed, 64) == NULL){ D("bcrypt failed"); rc = 1; goto BAILOUT; }
    if(!strcmp(pwdh, (char*)&pwdh_computed[0])){ rc = 0; }
  } else {
    D("Using libc: supporting MD5, SHA256, SHA512");
    if (!strcmp(pwdh, crypt(password, pwdh)))
      rc = 0;
  }

BAILOUT:
  backend_close();
  if(storage) free(storage);
  return rc == 0;
}
