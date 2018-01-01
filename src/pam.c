#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCT
#define PAM_SM_SESSION
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "debug.h"
#include "config.h"
#include "backend.h"
#include "homedir.h"

#define PAM_OPT_DEBUG			0x01
#define PAM_OPT_USE_FIRST_PASS		0x02
#define	PAM_OPT_TRY_FIRST_PASS		0x04
#define	PAM_OPT_ECHO_PASS		0x08


/*
 * Fetch module options
 */
void pam_options(int *flags, char **config_file, int argc, const char **argv)
{

  *config_file = CFGFILE; /* default */
  char** args = (char**)argv;
  /* Step through module arguments */
  for (; argc-- > 0; ++args){
    if (!strcmp(*args, "silent")) {
      *flags |= PAM_SILENT;
    } else if (!strcmp(*args, "debug")) {
      *flags |= PAM_OPT_DEBUG;
    } else if (!strcmp(*args, "use_first_pass")) {
      *flags |= PAM_OPT_USE_FIRST_PASS;
    } else if (!strcmp(*args, "try_first_pass")) {
      *flags |= PAM_OPT_TRY_FIRST_PASS;
    } else if (!strcmp(*args, "echo_pass")) {
      *flags |= PAM_OPT_ECHO_PASS;
    } else if (!strncmp(*args,"config_file=",12)) {
      *config_file = *args+12;
    } else {
      SYSLOG("unknown option: %s", *args);
    }
  }
  return;
}

/*
 * authenticate user
 */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *user, *password, *rhost;
  const void *item;
  int rc;
  const struct pam_conv *conv;
  struct pam_message msg;
  const struct pam_message *msgs[1];
  struct pam_response *resp;
  char* config_file = NULL;
  int mflags = 0;
  
  D("called");

  user = NULL; password = NULL; rhost = NULL;

  rc = pam_get_user(pamh, &user, NULL);
  if (rc != PAM_SUCCESS) { D("Can't get user: %s", pam_strerror(pamh, rc)); return rc; }
  
  rc = pam_get_item(pamh, PAM_RHOST, &item);
  if ( rc != PAM_SUCCESS) { SYSLOG("EGA: Unknown rhost: %s", pam_strerror(pamh, rc)); }

  rhost = (char*)item;
  if(rhost){ /* readconfig first, if using DBGLOG */
    SYSLOG("EGA: attempting to authenticate: %s (from %s)", user, rhost);
  } else {
    SYSLOG("EGA: attempting to authenticate: %s", user);
  }

  /* Grab the already-entered password if we might want to use it. */
  if (mflags & (PAM_OPT_TRY_FIRST_PASS | PAM_OPT_USE_FIRST_PASS)){
    rc = pam_get_item(pamh, PAM_AUTHTOK, &item);
    if (rc != PAM_SUCCESS){
      AUTHLOG("EGA: (already-entered) password retrieval failed: %s", pam_strerror(pamh, rc));
      return rc;
    }
  }

  password = (char*)item;
  /* The user hasn't entered a password yet. */
  if (!password && (mflags & PAM_OPT_USE_FIRST_PASS)){
    DBGLOG("EGA: password retrieval failed: %s", pam_strerror(pamh, rc));
    return PAM_AUTH_ERR;
  }

  pam_options(&mflags, &config_file, argc, argv);
  if(!readconfig(config_file)){
    D("Can't read config");
    return PAM_AUTH_ERR;
  }

  D("Asking %s for password", user);

  /* Get the password then */
  msg.msg_style = (mflags & PAM_OPT_ECHO_PASS)?PAM_PROMPT_ECHO_ON:PAM_PROMPT_ECHO_OFF;
  msg.msg = options->prompt;
  msgs[0] = &msg;

  rc = pam_get_item(pamh, PAM_CONV, &item);
  if (rc != PAM_SUCCESS){
    DBGLOG("EGA: conversation initialization failed: %s", pam_strerror(pamh, rc));
    return rc;
  }

  conv = (struct pam_conv *)item;
  rc = conv->conv(1, msgs, &resp, conv->appdata_ptr);
  if (rc != PAM_SUCCESS){
    DBGLOG("EGA: password conversation failed: %s", pam_strerror(pamh, rc));
    return rc;
  }
  
  rc = pam_set_item(pamh, PAM_AUTHTOK, (const void*)resp[0].resp);
  if (rc != PAM_SUCCESS){
    DBGLOG("EGA: setting password for other modules failed: %s", pam_strerror(pamh, rc));
    return rc;
  }

  /* Cleaning the message */
  memset(resp[0].resp, 0, strlen(resp[0].resp));
  free(resp[0].resp);
  free(resp);

  D("get it again after conversation");

  rc = pam_get_item(pamh, PAM_AUTHTOK, &item);
  password = (char*)item;
  if (rc != PAM_SUCCESS){
    SYSLOG("EGA: password retrieval failed: %s", pam_strerror(pamh, rc));
    return rc;
  }

  D("allowing empty passwords?");
  /* Check if empty password are disallowed */
  if ((!password || !*password) && (flags & PAM_DISALLOW_NULL_AUTHTOK)) { return PAM_AUTH_ERR; }
  
  /* Now, we have the password */
  if(backend_authenticate(user, password)){
    if(rhost){
      SYSLOG("EGA: user %s authenticated (from %s)", user, rhost);
    } else {
      SYSLOG("EGA: user %s authenticated", user);
    }
    return PAM_SUCCESS;
  }

  return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

/*
 * Check if account has expired
 */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *user;
  int rc;

  D("called");
  rc = pam_get_user(pamh, &user, NULL);
  if ( rc != PAM_SUCCESS){ D("EGA: Unknown user: %s", strerror(errno)); rc = PAM_SESSION_ERR; }

  if(!readconfig(CFGFILE)){ D("Can't read config"); return PAM_PERM_DENIED; }

  return account_valid(user);
}

/*
 * Refresh user in DB, Mount LegaFS, and Chroot to homedir
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *username;
  char *mountpoint = NULL, *rootdir_options = NULL;
  int rc, child;
  struct sigaction newsa, oldsa;
  bool restore_handler = false;

  rc = pam_get_user(pamh, &username, NULL);
  if ( rc != PAM_SUCCESS) { D("EGA: Unknown user: %s", pam_strerror(pamh, rc)); return rc; }

  if(!readconfig(CFGFILE)){ D("Can't read config"); return PAM_SESSION_ERR; }

  int slen_fuse = strlen(options->ega_fuse_dir),
      slen_dir  = strlen(options->ega_dir),
      slen_user = strlen(username);

  /* Construct mountpoint and rootdir_options */
  mountpoint = (char*)malloc(sizeof(char) * (slen_fuse+slen_user+2));
  if(!mountpoint) return PAM_SESSION_ERR;
  sprintf(mountpoint, "%s/%s", options->ega_fuse_dir, username);

  rootdir_options = (char*)malloc(sizeof(char) * (slen_dir+slen_user+11));
  if(!rootdir_options){ rc = PAM_SESSION_ERR; goto BAILOUT; }
  sprintf(rootdir_options, ",rootdir=%s/%s", options->ega_dir, username);

  D("Mounting LegaFS for user %s at %s", username, mountpoint);

  /*
   * This code arranges that the demise of the child does not cause
   * the application to receive a signal it is not expecting - which
   * may kill the application or worse.
   */
  memset(&newsa, '\0', sizeof(newsa));
  newsa.sa_handler = SIG_DFL;
  sigaction(SIGCHLD, &newsa, &oldsa);
  restore_handler = true;

  /* fork */
  child = fork();
  if (child < 0) { D("LegaFS fork failed: %s", strerror(errno)); rc = PAM_SESSION_ERR; goto BAILOUT; }

  if (child == 0) {
     /* if (pam_modutil_sanitize_helper_fds(pamh, PAM_MODUTIL_PIPE_FD, PAM_MODUTIL_PIPE_FD, PAM_MODUTIL_PIPE_FD) < 0) */
     /*   _exit(PAM_SESSION_ERR); */

    options->ega_fuse_flags = (char*)realloc(options->ega_fuse_flags, strlen(options->ega_fuse_flags)+strlen(rootdir_options)+sizeof(char));
    if(!options->ega_fuse_flags) { D("Could not build the mount options"); rc = PAM_SESSION_ERR; goto BAILOUT; }
    strcat(options->ega_fuse_flags, rootdir_options);

    /* exec the mkhomedir helper */
    D("Executing: %s %s -o %s", options->ega_fuse_exec, mountpoint, options->ega_fuse_flags);
    execlp(options->ega_fuse_exec, basename((char*)options->ega_fuse_exec), mountpoint, "-o", options->ega_fuse_flags, (char*)NULL);
    /* should not get here: exit with error */
    D("LegaFS is not available"); rc = PAM_SESSION_ERR; goto BAILOUT;
  }

  /* Child > 0 */
  if(waitpid(child, &rc, 0) < 0) { D("waitpid failed [%d]: %s", rc, strerror(errno)); rc = PAM_SESSION_ERR; goto BAILOUT; }
  if (!WIFEXITED(rc) || errno == EINTR) { D("Error occured while mounting a LegaFS: %s", strerror(errno)); rc = PAM_SESSION_ERR; goto BAILOUT; }

  rc = WEXITSTATUS(rc);
  if(rc) { D("Unable to mount LegaFS: %s", strerror(errno)); rc = PAM_SESSION_ERR; goto BAILOUT; }

  D("Restoring old handler");
  sigaction(SIGCHLD, &oldsa, NULL);   /* restore old signal handler */
  restore_handler = false;
 
  D("Chrooting");
  if (chdir(mountpoint)) { D("Unable to chdir to %s: %s", mountpoint, strerror(errno)); rc = PAM_SESSION_ERR; goto BAILOUT; }
  if (chroot(mountpoint)){ D("Unable to chroot(%s): %s", mountpoint, strerror(errno)); rc = PAM_SESSION_ERR; goto BAILOUT; }
 
  D("Session open: Success");
  rc = PAM_SUCCESS;

BAILOUT:
  if(restore_handler) sigaction(SIGCHLD, &oldsa, NULL);
  if(mountpoint) free(mountpoint);
  if(rootdir_options) free(rootdir_options);
  return rc;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
  const char *username;
  int rc;
  char* mountpoint;

  rc = pam_get_user(pamh, &username, NULL);
  if ( rc != PAM_SUCCESS) { D("EGA: Unknown user: %s", pam_strerror(pamh, rc)); return rc; }

  D("unmount LegaFS for %s (if not busy)", username);

  if(!readconfig(CFGFILE)){ D("Can't read config"); return PAM_SESSION_ERR; }

  int slen_fuse = strlen(options->ega_fuse_dir), slen_user = strlen(username);

  /* Construct mountpoint and rootdir_options */
  mountpoint = (char*)malloc(sizeof(char) * (slen_fuse+slen_user+2));
  if(!mountpoint) return PAM_SESSION_ERR;
  sprintf(mountpoint, "%s/%s", options->ega_fuse_dir, username);

  D("Unmount %s", mountpoint);
  rc = umount(mountpoint);
  
  if(rc){
    D("Unable to unmount %s: %s", mountpoint, strerror(errno));
  } else {
    /* Removing dir. Should be empty */
    rc = rmdir(mountpoint);
    if(rc) D("Unable to rmdir %s: %s", mountpoint, strerror(errno));
  }

  D("Session close: Success");
  free(mountpoint);
  return PAM_SUCCESS;
}
