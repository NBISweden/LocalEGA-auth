#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"
#include "config.h"

bool
create_ega_dir(const char* topdir, const char* username, uid_t uid, gid_t gid, const long int attrs){

  struct stat st;
  char* userdir = strjoina(topdir, "/", username);

  D1("Create EGA dir: %s", userdir);

  /* If we find something, we assume it's correct and return */
  if (stat(userdir, &st) == 0){ D1("homedir already there: %s", userdir); return true; }
  
  /* Create the new directory */
  if (mkdir(userdir, attrs)){ D2("unable to mkdir %o %s [%s]", (unsigned int)attrs, userdir, strerror(errno)); return false; }
  if (chown(userdir, uid, gid)){ D2("unable to change owernship to %d:%d [%s]", uid, gid, strerror(errno)); return false; }

  D1("homedir created: %s", userdir);
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
