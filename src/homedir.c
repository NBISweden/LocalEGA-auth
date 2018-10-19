#include <errno.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>

#include "utils.h"
#include "config.h"

int
create_ega_dir(const struct passwd *result){

  struct stat st;

  D1("Creating EGA dir: %s", result->pw_dir);

  /* If we find something, we assume it's correct and return */
  if (stat(result->pw_dir, &st) == 0){ D2("homedir already there: %s", result->pw_dir); return 0; }
  
  /* Create the new directory - not a recursive call. */
  if (mkdir(result->pw_dir, options->ega_dir_attrs)){
    D2("unable to mkdir %o %s [%s]", (unsigned int)options->ega_dir_attrs, result->pw_dir, strerror(errno));
    return 1;
  }
  if (chown(result->pw_dir, result->pw_uid, result->pw_gid)){
    D2("unable to change ownership to %d:%d [%s]", result->pw_uid, result->pw_gid, strerror(errno));
    return 1;
  }

  D2("homedir created: %s", result->pw_dir);
  return 0;
}
