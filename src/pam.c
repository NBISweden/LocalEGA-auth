#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
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

#include <limits.h>

#include "blowfish/ow-crypt.h"
#include "utils.h"
#include "backend.h"
#include "cega.h"

#define PAM_OPT_DEBUG			0x01
#define PAM_OPT_USE_FIRST_PASS		0x02
#define	PAM_OPT_TRY_FIRST_PASS		0x04
#define	PAM_OPT_ECHO_PASS		0x08

/*
 * Fetch module options
 */
void pam_options(int *flags, int argc, const char **argv)
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
    /* } else if (!strncmp(*args,"config_file=",12)) { */
    /*   *config_file = *args+12; */
    } else {
      D1("unknown option: %s", *args);
    }
  }
  return;
}

/* prototype definitions. See the end of the file */
static int _get_password_hash(const char* username, char** data);


/*
 * authenticate user
 */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *user = NULL, *password = NULL;
  const void *item;
  int rc;
  const struct pam_conv *conv;
  struct pam_message msg;
  const struct pam_message *msgs[1];
  struct pam_response *resp;
  int mflags = 0;
  
  D2("Getting auth PAM module options");

  rc = pam_get_user(pamh, &user, NULL);
  if (rc != PAM_SUCCESS) { D1("Can't get user: %s", pam_strerror(pamh, rc)); return rc; }
  
  rc = pam_get_item(pamh, PAM_RHOST, &item);
  if ( rc != PAM_SUCCESS) { D1("EGA: Unknown rhost: %s", pam_strerror(pamh, rc)); }
  D1("Authenticating %s%s%s", user, (item)?" from ":"", (item)?((char*)item):"");

  pam_options(&mflags, argc, argv);

  /* Grab the already-entered password if we might want to use it. */
  if (mflags & (PAM_OPT_TRY_FIRST_PASS | PAM_OPT_USE_FIRST_PASS)){
    rc = pam_get_item(pamh, PAM_AUTHTOK, &item);
    if (rc != PAM_SUCCESS){
      D1("(already-entered) password retrieval failed: %s", pam_strerror(pamh, rc));
      return rc;
    }
  }

  password = (char*)item;
  /* The user hasn't entered a password yet. */
  if (!password && (mflags & PAM_OPT_USE_FIRST_PASS)){
    D1("Password retrieval failed: %s", pam_strerror(pamh, rc));
    return PAM_AUTH_ERR;
  }

  D1("Asking %s for password", user);

  /* Get the password then */
  msg.msg_style = (mflags & PAM_OPT_ECHO_PASS)?PAM_PROMPT_ECHO_ON:PAM_PROMPT_ECHO_OFF;
  msg.msg = options->prompt;
  msgs[0] = &msg;

  rc = pam_get_item(pamh, PAM_CONV, &item);
  if (rc != PAM_SUCCESS){ D1("Conversation initialization failed: %s", pam_strerror(pamh, rc)); return rc; }

  conv = (struct pam_conv *)item;
  rc = conv->conv(1, msgs, &resp, conv->appdata_ptr);
  if (rc != PAM_SUCCESS){ D1("Password conversation failed: %s", pam_strerror(pamh, rc)); return rc; }
  
  rc = pam_set_item(pamh, PAM_AUTHTOK, (const void*)resp[0].resp);
  if (rc != PAM_SUCCESS){ D1("Setting password for other modules failed: %s", pam_strerror(pamh, rc)); return rc; }

  /* Cleaning the message */
  memset(resp[0].resp, 0, strlen(resp[0].resp));
  free(resp[0].resp);
  free(resp);

  D1("Get it again after conversation");

  rc = pam_get_item(pamh, PAM_AUTHTOK, &item);
  password = (char*)item;
  if (rc != PAM_SUCCESS){ D1("Password retrieval failed: %s", pam_strerror(pamh, rc)); return rc; }

  D1("Allowing empty passwords?");
  /* Check if empty password are disallowed */
  if ((!password || !*password) && (flags & PAM_DISALLOW_NULL_AUTHTOK)) { return PAM_AUTH_ERR; }
  
  /* Now, we have the password */
  D1("Authenticating user %s with password", user);

  _cleanup_str_ char* pwdh = NULL;
  rc = _get_password_hash(user, &pwdh);
  D2("Passwd hash: %s", pwdh);

  if(!pwdh || rc < 0){ D1("Could not load the password hash of '%s'", user); return PAM_AUTH_ERR; }

  if(!strncmp(pwdh, "$2", 2)){
    D2("Using Blowfish");
    char pwdh_computed[64];
    if( crypt_rn(password, pwdh, pwdh_computed, 64) == NULL){ D2("bcrypt failed"); return PAM_AUTH_ERR; }
    if(!strcmp(pwdh, (char*)&pwdh_computed[0])) { return PAM_SUCCESS; }
  } else {
    D2("Using libc: supporting MD5, SHA256, SHA512");
    if (!strcmp(pwdh, crypt(password, pwdh))){ return PAM_SUCCESS; }
  }

  D1("Authentication failed for %s", user);
  return PAM_AUTH_ERR;
}

/*
 * Mount LegaFS, and Chroot to homedir
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *username;
  char *mountpoint = NULL;
  int rc;
  int mflags = 0;
  /* char *mount_options = NULL; */
  /* struct sigaction newsa, oldsa; */
  /* int child; */

  D2("Getting open session PAM module options");
  pam_options(&mflags, argc, argv);

  if ( (rc = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) { D1("EGA: Unknown user: %s", pam_strerror(pamh, rc)); return rc; }

  /* Construct mountpoint and rootdir_options */
  mountpoint = strjoina(options->ega_dir, "/", username);
  /* D1("Mounting LegaFS for %s at %s", username, mountpoint); */
  /* mount_options = strjoina(options->ega_fuse_flags, ",user=", username); */

  /* /\* */
  /*  * This code arranges that the demise of the child does not cause */
  /*  * the application to receive a signal it is not expecting - which */
  /*  * may kill the application or worse. */
  /*  *\/ */
  /* memset(&newsa, '\0', sizeof(newsa)); */
  /* newsa.sa_handler = SIG_DFL; */
  /* sigaction(SIGCHLD, &newsa, &oldsa); */

  /* /\* fork *\/ */
  /* child = fork(); */
  /* if (child < 0) { D1("LegaFS fork failed: %s", strerror(errno)); return PAM_ABORT; } */

  /* if (child == 0) { */
  /*    /\* if (pam_modutil_sanitize_helper_fds(pamh, PAM_MODUTIL_PIPE_FD, PAM_MODUTIL_PIPE_FD, PAM_MODUTIL_PIPE_FD) < 0) *\/ */
  /*    /\*   _exit(PAM_SESSION_ERR); *\/ */
  /*   D1("Executing: %s %s -o %s", options->ega_fuse_exec, mountpoint, mount_options); */
  /*   execlp(options->ega_fuse_exec, basename((char*)options->ega_fuse_exec), mountpoint, "-o", mount_options, (char*)NULL); */
  /*   /\* should not get here: exit with error *\/ */
  /*   D1("LegaFS is not available"); */
  /*   _exit(errno); */
  /* } */

  /* /\* Child > 0 *\/ */
  /* if(waitpid(child, &rc, 0) < 0) { D1("waitpid failed [%d]: %s", rc, strerror(errno)); return PAM_ABORT; } */
  /* if (!WIFEXITED(rc) || errno == EINTR) { D1("Error occured while mounting a LegaFS: %s", strerror(errno)); return PAM_SESSION_ERR; } */

  /* sigaction(SIGCHLD, &oldsa, NULL); */

  /* rc = WEXITSTATUS(rc); */
  /* if(rc) { D1("Unable to mount LegaFS [Exit %d]", rc); return PAM_SESSION_ERR; } */


  D1("Setting umask to %o", options->ega_dir_umask);
  umask((mode_t)options->ega_dir_umask); /* ignore old mask */

  if( options->chroot ){

#ifdef DEBUG
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) { D1("Current working dir: %s\n", cwd); }
#endif
   
    D1("Chrooting to %s", mountpoint);
    if (chdir(mountpoint)) { D1("Unable to chdir to %s: %s", mountpoint, strerror(errno)); return PAM_SESSION_ERR; }
    if (chroot(mountpoint)){ D1("Unable to chroot(%s): %s", mountpoint, strerror(errno)); return PAM_SESSION_ERR; }
    
#ifdef DEBUG
    if (getcwd(cwd, sizeof(cwd)) != NULL) { D1("Chroot working dir: %s\n", cwd); }
#endif
  }

  D1("Session open: Success");
  return PAM_SUCCESS;
}

/*
 * Returning success because we are in the chrooted env
 * so no path to the user's cache entry
 */
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
  D1("Session close: Success");
  return PAM_SUCCESS;
}


/* Allow the account */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
  D1("Account: Checking cache expiration");
  int rc;
  const char *username;
  int mflags = 0;

  D2("Getting acct PAM module options");
  pam_options(&mflags, argc, argv);

  if ( (rc = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) { D1("EGA: Unknown user: %s", pam_strerror(pamh, rc)); return rc; }

  /* check database */
  bool use_backend = backend_opened();
  if(!use_backend){ D1("Backend disabled: Account allowed by default"); return PAM_SUCCESS; }

  if(!backend_has_expired(username)){ D1("Account valid for user '%s' [cached]", username); return PAM_SUCCESS; }

  /* Defining the CentralEGA callback */
  int cega_callback(char* uname, uid_t uid, char* password_hash, char* pubkey, char* gecos){
    /* assert same name */
    if( strcmp(username, uname) ){
      REPORT("Requested username %s not matching username response %s", username, uname);
      return PAM_CRED_UNAVAIL;
    }
    /* Add to database. Ignore result. */
    if(use_backend) backend_add_user(username, uid, password_hash, pubkey, gecos);
    return PAM_SUCCESS;
  }

  rc = cega_resolve(strjoina(options->cega_endpoint_name, username), cega_callback);

  if(rc == PAM_SUCCESS){ D1("Account valid for user '%s'", username); return PAM_SUCCESS; }

  REPORT("Account expired '%s'", username);
  return PAM_CRED_EXPIRED;
}

/*
 * setcred runs before and after session_open
 * which means, 'after' is in a chrooted-env, so setcred fails
 * (but before succeeds)
 * So a user is refreshed right before an attempts to open a session,
 * right after a successful authentication
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  D1("Set cred allowed");
  return PAM_SUCCESS;
}


/* Fetch the password hash, from either the database or CentralEGA.
 * Allocates a string into data. You have to clean it when you're done.
 */
static int
_get_password_hash(const char* username, char** data)
{
  int rc = 0;

  D1("Fetching the password hash of %s", username);

  /* check database */
  bool use_backend = backend_opened();
  if(use_backend && backend_get_password_hash(username, data)) return rc;

  /* Defining the CentralEGA callback */
  int _get_pwdh(char* uname, uid_t uid, char* password_hash, char* pubkey, char* gecos){
    int rc = 1;
    /* assert same name */
    if( strcmp(username, uname) ){
      REPORT("Requested username %s not matching username response %s", username, uname);
      return rc;
    }
    if(password_hash){ *data = strdup(password_hash); rc = 0; /* success */ }
    else { REPORT("No password hash found for user '%s'", username); }
    if(use_backend) backend_add_user(username, uid, password_hash, pubkey, gecos); // ignore result
    return rc;
  }

  return cega_resolve(strjoina(options->cega_endpoint_name, username), _get_pwdh);
}
