#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <crypt.h>
#include <sys/stat.h>

#include "debug.h"
#include "config.h"
#include "backend.h"
#include "cega.h"
#include "homedir.h"
#include "blowfish/ow-crypt.h"

/*
  We use 'buffer' to store the cache/username/item path.
  That way, we don't need to allocate strings
*/

static size_t storage_size = 1024;
static char* storage = NULL;

static int
_init_storage(void){
  D("Initializing storage to %zd chars", storage_size);
  storage = (char*)malloc(storage_size * sizeof(char) );
  if(!storage){ D("Could not allocate the internal storage"); return 1; }
  return 0;
}

static void _destroy_storage(void){
  D("Removing storage of %zd chars", storage_size);
  free((void*)storage);
  storage = NULL;
}

static bool _resize_storage(int factor){
  D("Resizing from %zd", storage_size);
  storage_size *= factor;
  D("Resizing to %zd", storage_size);
  if(!realloc(storage, storage_size * sizeof(char))){
    D("Could not resize the internal storage");
    return false;
  }
  return true;
}

static int
_copy2buffer(char **bufptr, const char* res, size_t *buflen)
{
  size_t slen = strlen(res);

  if(*buflen < slen+1) { D("buffer too small"); return 1; }

  strncpy(*bufptr, res, slen);
  (*bufptr)[slen] = '\0';

  *bufptr += slen + 1;
  *buflen -= slen + 1;
  
  return 0;
}

/*
 * Copies <cache_dir>/<username>[/item] to the buffer pointed by bufptr
 */
static int
name2path(const char* username, char* item, char **bufptr, size_t *buflen){
  
  if(_copy2buffer(bufptr, options->cache_dir, buflen)) { return 1; }
  *(*bufptr-1) = '/'; /* backtrack one char */

  if(_copy2buffer(bufptr, username, buflen)) { return 1; }

  if(item){
    (*bufptr)--; /* backtrack one char */
    if(_copy2buffer(bufptr, item, buflen)) { return 1; }
  }
  return 0;
}

static char*
load_file(char* path, char** bufptr, size_t* buflen){

  long length;
  FILE* f = NULL;
  char* content = *bufptr;

  f = fopen (path, "rb");
  if(!f){ return NULL; }

  /* Get the size */
  fseek (f, 0, SEEK_END);
  length = ftell(f);
  fseek (f, 0, SEEK_SET); // rewind

  while(*buflen < length + 1) {
    D("buffer too small. Doubling");
    if(!_resize_storage(2)) return NULL;
    *buflen += (storage_size/2);
  }

  fread(*bufptr, sizeof(char), length, f); // \0 terminated?

  fclose(f);
  return content;
}

/* connect to database */
bool
backend_open(int stayopen)
{
  D("called with args: stayopen: %d", stayopen);
  if(!readconfig(CFGFILE)){ D("Can't read config"); return false; }

  return (_init_storage() == 0);
}


/* close connection to database */
void
backend_close(void)
{ 
  D("called");
  _destroy_storage();
}


/*
 * 'convert' to struct passwd
 */
static enum nss_status
_get(const char* username, struct passwd *result, char **buffer, size_t *buflen, int *errnop)
{

  char* path = *buffer;
  struct stat st;
  name2path(username, "", buffer, buflen);

  D("Path to %s: %s", username, path);

  if(stat(path,&st)) return NSS_STATUS_NOTFOUND;

  /* ok, cache found */
  D("Convert to passwd struct");

  result->pw_name = *buffer;
  if(_copy2buffer(buffer, username, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  result->pw_passwd = *buffer;
  if(_copy2buffer(buffer, "x", buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  result->pw_gecos = *buffer;
  if(_copy2buffer(buffer, options->ega_gecos, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  result->pw_shell = *buffer;
  if(_copy2buffer(buffer, options->ega_shell, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

  result->pw_uid = options->ega_uid;
  result->pw_gid = options->ega_gid;

  /* For the homedir: ega_fuse_dir/username */
  result->pw_dir = *buffer;
  if(_copy2buffer(buffer, options->ega_fuse_dir, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
  *(*buffer-1) = '/'; /* backtrack one char */
  if(_copy2buffer(buffer, username, buflen)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }

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
bool
backend_add_user(const char* username, const char* pwdh, const char* pubkey)
{
  bool success = true;
  D("Not implemented");
  return success;
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
  if( rc ){ D("Fetch CEGA error"); return NSS_STATUS_NOTFOUND; }

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
  int status = false;
  char* pwdh = NULL;
  char* path = storage;
  char** bufptr = &storage;
  size_t buflen = storage_size;

  if(!backend_open(0)) return false;

  while(name2path(username, "/password_hash", bufptr, &buflen)) {
    D("Buffer too small. Doubling.");
    if(!_resize_storage(2)) goto BAILOUT;
    buflen += (storage_size/2);
  }

  pwdh = load_file(path, bufptr, &buflen);

  if(!pwdh){ D("could not load the password_hash from %s", path); goto BAILOUT; }

  if(!strncmp(pwdh, "$2", 2)){
    D("Using Blowfish");
    char pwdh_computed[64];
    if( crypt_rn(password, pwdh, pwdh_computed, 64) == NULL){
      D("bcrypt failed");
      goto BAILOUT;
    }
    if(!strcmp(pwdh, (char*)&pwdh_computed[0]))
      status = true;
  } else {
    D("Using libc: supporting MD5, SHA256, SHA512");
    if (!strcmp(pwdh, crypt(password, pwdh)))
      status = true;
  }

BAILOUT:
  backend_close();
  return status;
}
