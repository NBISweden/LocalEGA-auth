#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

#include "utils.h"
#include "config.h"

bool
create_ega_dir(const struct passwd *result, const long int attrs){

  struct stat st;

  D1("Creating EGA dir: %s", result->pw_dir);

  /* If we find something, we assume it's correct and return */
  if (stat(result->pw_dir, &st) == 0){ D2("homedir already there: %s", result->pw_dir); return true; }
  
  /* Create the new directory */
  if (mkdir(result->pw_dir, attrs)){
    D2("unable to mkdir %o %s [%s]", (unsigned int)attrs, result->pw_dir, strerror(errno));
    return false;
  }
  if (chown(result->pw_dir, result->pw_uid, result->pw_gid)){
    D2("unable to change owernship to %d:%d [%s]", result->pw_uid, result->pw_gid, strerror(errno));
    return false;
  }

  D2("homedir created: %s", result->pw_dir);
  return true;
}

void
remove_ega_dir(const char* topdir, const char* username){

  char* userdir = strjoina(topdir, "/", username);

  D2("Attempting to remove EGA dir: %s", userdir);

  int err = rmdir(userdir);

  D2("EGA dir %s %sremoved", userdir, (err)?"not ":"");
  if(err){ D2("Reason: %s", strerror(errno)); }

  return;
}
