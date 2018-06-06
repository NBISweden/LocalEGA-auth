#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "utils.h"
#include "config.h"
#include "backend.h"

/*
  We use strjoina(...) to allocate on the stack
  That way, we don't need to free that mem

  We use also __attribute__((cleanup)) to free the other allocated mem
*/

int
backend_get_item(const char* username, const char* item, char** content){

  long length;
  _cleanup_file_ FILE* f = NULL;

  D2("Loading %s file for user %s", item, username);

  char* path = strjoina(options->cache_dir, "/", username, "/", item);

  D2("Loading %s", path);

  f = fopen (path, "rb");
  if( !f || ferror(f) ){ D2("Could not open file: %s", path); return -2; }

  /* Get the size */
  fseek (f, 0, SEEK_END);
  length = ftell(f) + 1;
  fseek (f, 0, SEEK_SET); // rewind

  *content = (char*)malloc(sizeof(char) * length);
  return fread(*content, sizeof(char), length, f); // \0 terminated?
}

int
backend_set_item(const char* username, const char* item, const char* content){

  _cleanup_file_ FILE* f = NULL;
  char* path = strjoina(options->cache_dir, "/", username, "/", item);

  D2("Opening file: %s", path);

  f = fopen (path, "wb");
  if(!f){ D2("Could not open file: %s", path); return -2; }
  chmod(path, 0600);

  D2("Storing data: %s", content);
  return (fwrite(content, sizeof(char), strlen(content), f) > 0)?0:-2;
}

/*
 * Assumes config file already loaded
 */
bool
backend_add_user(const char* username, const char* pwdh, const char* pubkey)
{
  char* userdir = strjoina(options->cache_dir, "/", username);
  D1("Adding '%s' to cache [%s]", username, userdir);
  /* Create the new directory */
  if (mkdir(userdir, 0700) && errno != EEXIST){ D2("unable to mkdir 700 %s [%s]", userdir, strerror(errno)); return false; }

  /* Store the files */
  if( pwdh && (backend_set_item(username, PASSWORD, pwdh) < 0) ){
    D2("Problem storing password hash for user %s", username); return false;
  }
  if( pubkey && (backend_set_item(username, PUBKEY, pubkey) < 0)){
    D2("Problem storing public key for user %s", username); return false;
  }

  char seconds[20]; // Laaaaaaaaaaaaarge enough!
  sprintf(seconds, "%ld", time(NULL));
  if( backend_set_item(username, LAST_ACCESSED, seconds) < 0 ){
    D2("Problem storing expiration for user %s", username);
    return false;
  }

  return true;
}

/*
 * Check the cache entry:
 *       - /ega/cache/<username> exists
 *       - it is a dir
 *       - it is 700
 *       - (now - last_access) < CACHE_TTL
 */
bool
backend_user_found(const char* username){
  D2("Looking for '%s'", username);
  char* path = strjoina(options->cache_dir, "/", username);
  D2("Cache entry for %s: %s", username, path);

  struct stat st;

  /* Check path exists */
  if( stat(path, &st) ){ 
    if (errno != ENOENT){ D3("stat(%s) failed", path); }
    return false;
  }

  /* Check if path is a directory and is -rwx  */
  if( !S_ISDIR(st.st_mode) ){ D3("%s is not a directory", path); return false; }
  if( (st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != S_IRWXU ){ D3("%s is not 700", path); return false; }

  D3("%s is a dir and 700", path);

  D2("Checking cache TTL");

  _cleanup_str_ char* last_accessed = NULL;
  bool valid = false;
  int rc = backend_get_item(username, LAST_ACCESSED, &last_accessed);
  if(!last_accessed || rc < 0){ valid = false; }
  else {
    valid = ( difftime(time(NULL), ((time_t)strtol(last_accessed, NULL, 10))) < CACHE_TTL );
  }
  D1("Cache %s",(valid)?"valid":"too old");
  return valid;
}

/*
 * 'convert' to struct passwd
 *
 * We use -1 in case the buffer is too small
 *         0 on success
 *         1 on cache miss / user not found
 */
int
backend_convert(const char* username, struct passwd *result, char* buffer, size_t buflen)
{
  if( !backend_user_found(username) ){ /* cache_miss */ return 1; }

  /* ok, cache found */
  D3("Backend convert for %s", username);
  if( copy2buffer(username, &(result->pw_name), &buffer, &buflen) < 0 ) { return -1; }

  if( copy2buffer("x", &(result->pw_passwd), &buffer, &buflen) < 0 ) { return -1; }

  if( copy2buffer(options->ega_gecos, &(result->pw_gecos), &buffer, &buflen) < 0 ) { return -1; }

  if( copy2buffer(options->ega_shell, &(result->pw_shell), &buffer, &buflen) < 0 ) { return -1; }

  result->pw_uid = options->ega_uid;
  result->pw_gid = options->ega_gid;

  /* For the homedir: ega_dir/username */
  if( copy2buffer(options->ega_dir, &(result->pw_dir), &buffer, &buflen) < 0 ) { return -1; }
  *(buffer-1) = '/'; /* backtrack one char */
  if( copy2buffer(username, NULL, &buffer, &buflen) < 0) { return -1; }

  D2("Found: %s", username);
  return 0;
}
