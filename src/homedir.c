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

  if(!userdir){ D("no space for user directory"); return false; }

  D("Create EGA dir: %s", userdir);

  /* If we find something, we assume it's correct and return */
  if (stat(userdir, &st) == 0){ D("homedir already there: %s", userdir); return true; }
  
  /* Create the new directory */
  if (mkdir(userdir, attrs)){ D("unable to mkdir %o %s [%s]", (unsigned int)attrs, userdir, strerror(errno)); return false; }
  if (chown(userdir, uid, gid)){ D("unable to change owernship to %d:%d [%s]", uid, gid, strerror(errno)); return false; }

  D("homedir created: %s", userdir);
  return true;
}

void
remove_ega_dir(const char* topdir, const char* username){

  int err;

  char* userdir = strjoina(topdir, "/", username);

  if(!userdir){ D("no space for user directory"); return; }
    
  D("Attempting to remove EGA dir: %s", userdir);

  err = rmdir(userdir);

  D("EGA dir %s %sremoved", userdir, (err)?"not ":"");
  if(err) D("Reason: %s", strerror(errno));

  free(userdir);
  return;
}
