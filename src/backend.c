#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <libpq-fe.h>
#include <crypt.h>

#include "debug.h"
#include "config.h"
#include "backend.h"
#include "cega.h"
#include "homedir.h"
#include "blowfish/ow-crypt.h"

static PGconn* conn;

/* connect to database */
bool
backend_open(int stayopen)
{
  D("called with args: stayopen: %d", stayopen);
  if(!readconfig(CFGFILE)){ D("Can't read config"); return false; }
  if(!conn){ 
    DBGLOG("Connection to: %s", options->db_connstr);
    conn = PQconnectdb(options->db_connstr);
  }
	  
  if(PQstatus(conn) != CONNECTION_OK) {
    SYSLOG("PostgreSQL connection failed: '%s'", PQerrorMessage(conn));
    backend_close(); /* reentrant */
    return false;
  }
  D("DB Connection: %p", conn);

  return true;
}


/* close connection to database */
void
backend_close(void)
{ 
  D("called");
  if (conn) PQfinish(conn);
  conn = NULL;
}

/*
  Assign a single value to *p from the specified row in the result.
  We use 'buffer' to store the result values, and increase its size if necessary.
  That way, we don't allocate strings for struct passwd
*/
static int
_copy2buffer(const char* res, char **p, char **buf, size_t *buflen, int *errnop)
{
  size_t slen = strlen(res);

  if(*buflen < slen+1) {
    *errnop = ERANGE;
    D("**************** try again");
    return 1;
  }
  strncpy(*buf, res, slen);
  (*buf)[slen] = '\0';

  *p = *buf; /* where is the value inside buffer */
  
  *buf += slen + 1;
  *buflen -= slen + 1;
  
  return 0;
}

/*
 * 'convert' a PGresult to struct passwd
 */
enum nss_status
get_from_db(const char* username, struct passwd *result, char **buffer, size_t *buflen, int *errnop)
{
  enum nss_status status = NSS_STATUS_NOTFOUND;
  const char* params[1] = { username };
  PGresult *res;
  char *dummy;
  
  D("Prepared Statement with %s: %s", username, options->get_ent);
  res = PQexecParams(conn, options->get_ent, 1, NULL, params, NULL, NULL, 0);

  /* Check answer */
  if(PQresultStatus(res) != PGRES_TUPLES_OK || !PQntuples(res)) goto BAILOUT;

  D("Convert to passwd struct");
  /* no error, let's convert the result to a struct pwd */
  if(_copy2buffer(username          , &(result->pw_name)  , buffer, buflen, errnop)) { status = NSS_STATUS_TRYAGAIN; goto BAILOUT; }
  if(_copy2buffer("x"               , &(result->pw_passwd), buffer, buflen, errnop)) { status = NSS_STATUS_TRYAGAIN; goto BAILOUT; }
  if(_copy2buffer(options->ega_gecos, &(result->pw_gecos) , buffer, buflen, errnop)) { status = NSS_STATUS_TRYAGAIN; goto BAILOUT; }
  if(_copy2buffer(options->ega_shell, &(result->pw_shell) , buffer, buflen, errnop)) { status = NSS_STATUS_TRYAGAIN; goto BAILOUT; }

  /* For the homedir: ega_fuse_dir/username */
  if(_copy2buffer(options->ega_fuse_dir, &(result->pw_dir), buffer, buflen, errnop)) { status = NSS_STATUS_TRYAGAIN; goto BAILOUT; }
  *(*buffer-1) = '/'; /* backtrack one char */
  if(_copy2buffer(username, &dummy, buffer, buflen, errnop)) { status = NSS_STATUS_TRYAGAIN; goto BAILOUT; }

  result->pw_uid = options->ega_uid;
  result->pw_gid = options->ega_gid;

  D("Found: %s", username);
  status = NSS_STATUS_SUCCESS;

BAILOUT:
  PQclear(res);
  return status;
}

/*
 * refresh the user last accessed date
 */
int
session_refresh_user(const char* username)
{
  int status = PAM_SESSION_ERR;
  const char* params[1] = { username };
  PGresult *res;

  if(!backend_open(0)) return PAM_SESSION_ERR;

  D("Refreshing user %s", username);
  res = PQexecParams(conn, "SELECT refresh_user($1)", 1, NULL, params, NULL, NULL, 0);

  status = (PQresultStatus(res) != PGRES_TUPLES_OK)?PAM_SUCCESS:PAM_SESSION_ERR;

  PQclear(res);
  backend_close();
  return status;
}

/*
 * Has the account expired
 */
int
account_valid(const char* username)
{
  int status = PAM_PERM_DENIED;
  const char* params[1] = { username };
  PGresult *res;

  if(!backend_open(0)) return PAM_PERM_DENIED;

  D("Prepared Statement: %s with %s", options->get_account, username);
  res = PQexecParams(conn, options->get_account, 1, NULL, params, NULL, NULL, 0);

  /* Check answer */
  status = (PQresultStatus(res) == PGRES_TUPLES_OK)?PAM_SUCCESS:PAM_ACCT_EXPIRED;

  PQclear(res);
  backend_close();
  return status;
}

/* Assumes backend is open */
bool
add_to_db(const char* username, const char* pwdh, const char* pubkey)
{
  const char* params[3] = { username, pwdh, pubkey };
  PGresult *res;
  bool success;

  D("Prepared Statement: %s", options->add_user);
  D("with VALUES('%s','%s','%s')", username, pwdh, pubkey);
  res = PQexecParams(conn, options->add_user, 3, NULL, params, NULL, NULL, 0);

  success = (PQresultStatus(res) == PGRES_TUPLES_OK);
  if(!success) D("%s", PQerrorMessage(conn));
  PQclear(res);
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

  status = get_from_db(username, result, buffer, buflen, errnop);
  if (status == NSS_STATUS_SUCCESS) return status;

  /* OK, User not found in DB */

  /* if CEGA disabled */
  if(!options->with_cega){
    D("Contacting cega for user %s is disabled", username);
    return NSS_STATUS_NOTFOUND;
  }
    
  if(!fetch_from_cega(username, buffer, buflen, errnop))
    return NSS_STATUS_NOTFOUND;

  /* User retrieved from Central EGA, try again the DB */
  status = get_from_db(username, result, buffer, buflen, errnop);
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
  const char* params[1] = { username };
  const char* pwdh = NULL;
  PGresult *res;

  if(!backend_open(0)) return false;

  D("Prepared Statement: %s with %s", options->get_password, username);
  res = PQexecParams(conn, options->get_password, 1, NULL, params, NULL, NULL, 0);

  /* Check answer */
  if(PQresultStatus(res) != PGRES_TUPLES_OK || !PQntuples(res)) goto BAIL_OUT;
  
  /* no error, so fetch the result */
  pwdh = strdup(PQgetvalue(res, 0, 0)); /* row 0, col 0 */

  if(!strncmp(pwdh, "$2", 2)){
    D("Using Blowfish");
    char pwdh_computed[64];
    if( crypt_rn(password, pwdh, pwdh_computed, 64) == NULL){
      D("bcrypt failed");
      goto BAIL_OUT;
    }
    if(!strcmp(pwdh, (char*)&pwdh_computed[0]))
      status = true;
  } else {
    D("Using libc: supporting MD5, SHA256, SHA512");
    if (!strcmp(pwdh, crypt(password, pwdh)))
      status = true;
  }

BAIL_OUT:
  PQclear(res);
  if(pwdh) free((void*)pwdh);
  backend_close();
  return status;
}
