#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h> /* for basename */
#include <crypt.h>
#include <time.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCT
#define PAM_SM_SESSION
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "utils.h"
#include "config.h"
#include "backend.h"
#include "blowfish/ow-crypt.h"

#define PAM_OPT_DEBUG			0x01
#define PAM_OPT_USE_FIRST_PASS		0x02
#define	PAM_OPT_TRY_FIRST_PASS		0x04
#define	PAM_OPT_ECHO_PASS		0x08

/*
 * Fetch module options
 */
void pam_options(int *flags, char **config_file, int argc, const char **argv)
{
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
DECLARE_CLEANUP(pwdh);

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
  _cleanup_conf_ char* config_file = NULL;
  int mflags = 0;
  
  D("Getting auth PAM module options");

  user = NULL; password = NULL; rhost = NULL;

  rc = pam_get_user(pamh, &user, NULL);
  if (rc != PAM_SUCCESS) { D("Can't get user: %s", pam_strerror(pamh, rc)); return rc; }
  
  rc = pam_get_item(pamh, PAM_RHOST, &item);
  if ( rc != PAM_SUCCESS) { SYSLOG("EGA: Unknown rhost: %s", pam_strerror(pamh, rc)); }

  rhost = (char*)item;
  if(rhost){ /* readconfig first, if using DBGLOG */
    D("EGA: attempting to authenticate: %s (from %s)", user, rhost);
  } else {
    D("EGA: attempting to authenticate: %s", user);
  }

  pam_options(&mflags, &config_file, argc, argv);

  /* Grab the already-entered password if we might want to use it. */
  if (mflags & (PAM_OPT_TRY_FIRST_PASS | PAM_OPT_USE_FIRST_PASS)){
    rc = pam_get_item(pamh, PAM_AUTHTOK, &item);
    if (rc != PAM_SUCCESS){
      D("EGA: (already-entered) password retrieval failed: %s", pam_strerror(pamh, rc));
      return rc;
    }
  }

  password = (char*)item;
  /* The user hasn't entered a password yet. */
  if (!password && (mflags & PAM_OPT_USE_FIRST_PASS)){
    DBGLOG("EGA: password retrieval failed: %s", pam_strerror(pamh, rc));
    return PAM_AUTH_ERR;
  }

  _cleanup_str_(pwdh) char* pwdh = NULL;
  if(!config_file){ config_file = CFGFILE; /* default */ }
  if(!loadconfig(config_file)){ D("Can't read config"); return PAM_AUTH_ERR; }

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
  D("Authenticating user %s with password", user);

  rc = backend_get_item(user, PASSWORD, &pwdh);

  if(!pwdh || rc < 0){ D("could not load the last_accessed time for user %s", user); return PAM_AUTH_ERR; }

  if(!strncmp(pwdh, "$2", 2)){
    D("Using Blowfish");
    char pwdh_computed[64];
    if( crypt_rn(password, pwdh, pwdh_computed, 64) == NULL){ D("bcrypt failed"); return PAM_AUTH_ERR; }
    if(!strcmp(pwdh, (char*)&pwdh_computed[0])) { return PAM_SUCCESS; }
  } else {
    D("Using libc: supporting MD5, SHA256, SHA512");
    if (!strcmp(pwdh, crypt(password, pwdh))){ return PAM_SUCCESS; }
  }

  SYSLOG("EGA: authentication failed for %s", user);
  return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  D("------------- setcred -------------");
  return PAM_SUCCESS;
}

/*
 * Check if account has expired
 */
DECLARE_CLEANUP(last);

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int rc = PAM_PERM_DENIED;
  const char *username;
  _cleanup_conf_ char* config_file = NULL;
  int mflags = 0;

  D("Getting account PAM module options");
  pam_options(&mflags, &config_file, argc, argv);

  if ( (rc = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) { D("EGA: Unknown user: %s", pam_strerror(pamh, rc)); return rc; }

  D("Checking account validity for user %s", username);
  _cleanup_str_(last) char* last_accessed = NULL;
  if(!config_file){ config_file = CFGFILE; /* default */ }
  if(!loadconfig(config_file)){ D("Can't read config"); return PAM_ABORT; }

  rc = backend_get_item(username, LAST_ACCESSED, &last_accessed);
  if(!last_accessed || rc < 0){ D("could not load the last_accessed time for user %s", username); return PAM_ACCT_EXPIRED; }

  return ( difftime(time(NULL), ((time_t)strtol(last_accessed, NULL, 10))) > EGA_ACCOUNT_EXPIRATION )?PAM_SUCCESS:PAM_ACCT_EXPIRED;
}

/*
 * Refresh user in DB, Mount LegaFS, and Chroot to homedir
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *username;
  char *mountpoint = NULL, *mount_options = NULL;
  int rc, child;
  struct sigaction newsa, oldsa;
  _cleanup_conf_ char* config_file = NULL;
  int mflags = 0;

  pam_options(&mflags, &config_file, argc, argv);

  if ( (rc = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) { D("EGA: Unknown user: %s", pam_strerror(pamh, rc)); return rc; }

  if(!config_file){ config_file = CFGFILE; /* default */ }
  if(!loadconfig(config_file)){ D("Can't read config"); return PAM_SESSION_ERR; }

  /* Construct mountpoint and rootdir_options */
  mountpoint = strjoina(options->ega_fuse_dir, "/", username);
  mount_options = strjoina(options->ega_fuse_flags, ",rootdir=", options->ega_dir, "/", username, ",user=", username);
  D("Mounting LegaFS for user %s at %s", username, mountpoint);

  /*
   * This code arranges that the demise of the child does not cause
   * the application to receive a signal it is not expecting - which
   * may kill the application or worse.
   */
  memset(&newsa, '\0', sizeof(newsa));
  newsa.sa_handler = SIG_DFL;
  sigaction(SIGCHLD, &newsa, &oldsa);

  /* fork */
  child = fork();
  if (child < 0) { D("LegaFS fork failed: %s", strerror(errno)); return PAM_ABORT; }

  if (child == 0) {
     /* if (pam_modutil_sanitize_helper_fds(pamh, PAM_MODUTIL_PIPE_FD, PAM_MODUTIL_PIPE_FD, PAM_MODUTIL_PIPE_FD) < 0) */
     /*   _exit(PAM_SESSION_ERR); */

    D("Executing: %s %s -o %s", options->ega_fuse_exec, mountpoint, mount_options);
    execlp(options->ega_fuse_exec, basename((char*)options->ega_fuse_exec), mountpoint, "-o", mount_options, (char*)NULL);
    /* should not get here: exit with error */
    D("LegaFS is not available");
    cleanconfig();
    _exit(errno);
  }

  /* Child > 0 */
  if(waitpid(child, &rc, 0) < 0) { D("waitpid failed [%d]: %s", rc, strerror(errno)); return PAM_ABORT; }
  if (!WIFEXITED(rc) || errno == EINTR) { D("Error occured while mounting a LegaFS: %s", strerror(errno)); return PAM_SESSION_ERR; }

  sigaction(SIGCHLD, &oldsa, NULL);

  rc = WEXITSTATUS(rc);
  if(rc) { D("Unable to mount LegaFS [Exit %d]", rc); return PAM_SESSION_ERR; }

  D("Chrooting to %s", mountpoint);
  if (chdir(mountpoint)) { D("Unable to chdir to %s: %s", mountpoint, strerror(errno)); return PAM_SESSION_ERR; }
  if (chroot(mountpoint)){ D("Unable to chroot(%s): %s", mountpoint, strerror(errno)); return PAM_SESSION_ERR; }

  D("Session open: Success");
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
  int rc = PAM_SESSION_ERR;
  const char *username;
  _cleanup_conf_ char* config_file = NULL;
  int mflags = 0;

  D("called");
  pam_options(&mflags, &config_file, argc, argv);

  if ( (rc = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) { D("EGA: Unknown user: %s", pam_strerror(pamh, rc)); return rc; }

  if(!config_file){ config_file = CFGFILE; /* default */ }
  if(!loadconfig(config_file)){ D("Can't read config"); return PAM_SESSION_ERR; }

  D("Refreshing user %s", username);

  char seconds[65];
  sprintf(seconds, "%ld", time(NULL));
  return (backend_set_item(username, LAST_ACCESSED, seconds) > 0)?PAM_SUCCESS:PAM_SESSION_ERR;
}
