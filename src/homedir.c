#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "debug.h"
#include "config.h"

static char*
_expand_dir(const char* topdir, const char* username){
  char* d = (char*)malloc(sizeof(char)*(strlen(topdir)+strlen(username)+1));
  if(d) sprintf(d, "%s/%s", topdir, username);
  return d;
}

bool
create_ega_dir(const char* topdir, const char* username, uid_t uid, gid_t gid, const long int attrs){

  struct stat st;
  bool status = false;
  char* userdir = _expand_dir(topdir,username);

  if(!userdir){
    D("no space for user directory");
    return false;
  }

  D("Create EGA dir: %s", userdir);

  /* If we find something, we assume it's correct and return */
  if (stat(userdir, &st) == 0){
    D("homedir already there: %s", userdir);
    goto BAILOUT;
  }
  
  /* Create the new directory */
  if (mkdir(userdir, attrs)){
    D("unable to mkdir %o %s [%s]", (unsigned int)attrs, userdir, strerror(errno));
    goto BAILOUT;
  }

  if (chown(userdir, uid, gid)){
    D("unable to change owernship to %d:%d [%s]", uid, gid, strerror(errno));
    goto BAILOUT;
  }

  status = true;
  D("homedir created: %s", userdir);

BAILOUT:
  if(userdir)free(userdir);
  return status;
}

void
remove_ega_dir(const char* topdir, const char* username){

  int err;

  char* userdir = _expand_dir(topdir,username);

  if(!userdir){ D("no space for user directory"); return; }
    
  D("Attempting to remove EGA dir: %s", userdir);

  err = rmdir(userdir);

  D("EGA dir %s %sremoved", userdir, (err)?"not ":"");
  if(err) D("Reason: %s", strerror(errno));

  free(userdir);
  return;
}
