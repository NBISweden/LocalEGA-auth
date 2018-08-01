#include <stdio.h>
#include <time.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <errno.h>
#include <syslog.h>

#include "utils.h"
#include "backend.h"

/* DB schema */
#define EGA_SCHEMA_FMT "CREATE TABLE IF NOT EXISTS users (                      \
                          username TEXT UNIQUE PRIMARY KEY ON CONFLICT REPLACE, \
                          uid      INTEGER CHECK (uid >= %d),                   \
                          pwdh     TEXT,				        \
		          pubkey   TEXT,	                                \
		          gecos    TEXT,					\
                          inserted REAL DEFAULT (strftime('%%s','now'))	        \
                        ) WITHOUT ROWID;"

/* WITHOUT ROWID works only from 3.8.2 */


static sqlite3* db = NULL;
char* syslog_name = "EGA";

/*
 * Constructor/Destructor when the library is loaded
 *
 * See: http://man7.org/linux/man-pages/man3/dlopen.3.html
 *
 */
__attribute__((constructor))
static void
init(void)
{
  D3("Initializing the ega library");
  backend_open();
#ifdef DEBUG
  openlog (syslog_name, (LOG_CONS|LOG_NDELAY|LOG_PID), 0);
#endif
}

__attribute__((destructor))
static void
destroy(void)
{
  D3("Cleaning up the ega library");
#ifdef DEBUG
  closelog ();
#endif
  backend_close(); 
}

inline bool
backend_opened(void)
{
  return db && sqlite3_errcode(db) == SQLITE_OK;
}

void
backend_open(void)
{
  D2("Opening backend");
  if( !loadconfig() ){ REPORT("Invalid configuration"); return; }
  if( backend_opened() ){ D1("Already opened"); return; }

  D1("Connection to: %s", options->db_path);
  sqlite3_open(options->db_path, &db); /* owned by root and rw-r--r-- */
  if (db == NULL){ D1("Failed to allocate database handle"); return; }
  D3("DB Connection: %p", db);
  
  if( sqlite3_errcode(db) != SQLITE_OK) {
    D1("Failed to open DB: [%d] %s", sqlite3_extended_errcode(db), sqlite3_errstr(sqlite3_extended_errcode(db)));
    return;
  }
  
  /* create table */
  D2("Creating the database schema");
  sqlite3_stmt *stmt;
  char schema[1000]; /* Laaaarge enough! */
  sprintf(schema, EGA_SCHEMA_FMT, options->uid_shift);
  sqlite3_prepare_v2(db, schema, -1, &stmt, NULL);
  if (!stmt || sqlite3_step(stmt) != SQLITE_DONE) { D1("ERROR creating table: %s", sqlite3_errmsg(db)); }
  sqlite3_finalize(stmt);
}

void
backend_close(void)
{
  D2("Closing database backend");
  if(db) sqlite3_close(db);
  cleanconfig();
}


/*
 * Assumes config file already loaded and backend open
 */
int
backend_add_user(const char* username,
		 uid_t uid,
		 const char* pwdh,
		 const char* pubkey,
		 const char* gecos)
{
  sqlite3_stmt *stmt = NULL;

  D1("Insert %s into cache", username);

  /* The entry will be updated if already present */
  sqlite3_prepare_v2(db, "INSERT INTO users (username,uid,pwdh,pubkey,gecos) VALUES(?1,?2,?3,?4,?5)", -1, &stmt, NULL);
  if(!stmt){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return false; }

  sqlite3_bind_text(stmt,   1, username, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt,    2, uid                        );
  sqlite3_bind_text(stmt,   3, pwdh    , -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt,   4, pubkey  , -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt,   5, gecos   , -1, SQLITE_STATIC);

  /* We should acquire a RESERVED lock.
     See: https://www.sqlite.org/lockingv3.html#writing
     When the lock is taken, the database returns SQLITE_BUSY.
     So...
     That should be ok with a busy-loop. (Alternative: sleep(0.5)).
     It is highly unlikely that this process will starve.
     All other process will not keep the database busy forever.
  */
  while( sqlite3_step(stmt) == SQLITE_BUSY ); // a RESERVED lock is taken

  /* Execute the query. */
  int rc = (sqlite3_step(stmt) == SQLITE_DONE)?0:1;
  if(rc) D1("Execution error: %s", sqlite3_errmsg(db));
  sqlite3_finalize(stmt);
  return rc;
}

static inline int
_col2uid(sqlite3_stmt *stmt, int col, uid_t *uid)
{
  if(sqlite3_column_type(stmt, col) != SQLITE_INTEGER){ D1("Column %d is not a int", col); return 1; }
  *uid = (uid_t)sqlite3_column_int(stmt, col);
  /* if( *uid <= options->uid_shift ){ D1("User id too low: %u", *uid); return 2; } */
  return 0;
}

static inline int
_col2txt(sqlite3_stmt *stmt, int col, char** data, char **buffer, size_t* buflen)
{
  if(sqlite3_column_type(stmt, col) != SQLITE_TEXT){ D1("The colum %d is not a string", col); return 1; }
  char* s = (char*)sqlite3_column_text(stmt, col);
  if( s == NULL ){ D1("Memory allocation error"); return 1; }
  if( copy2buffer(s, data, buffer, buflen) < 0 ) { return -1; }
  return 0;
}

/*
 * 'convert' to struct passwd
 *
 * We use -1 in case the buffer is too small
 *         0 on success
 *         1 on cache miss / user not found
 *         error otherwise
 */

/*
 * Check the cache entry not expired
 */
static inline bool
backend_stmt_valid(sqlite3_stmt* stmt, int column)
{
  /* cache miss */
  if(sqlite3_step(stmt) != SQLITE_ROW) { D2("No SQL row"); return false; }

  /* /\* checking expiration *\/ */
  /* if(sqlite3_column_type(stmt, column) != SQLITE_FLOAT){ D1("The expiration is not a float"); return false; } */
  /* double created_at = (time_t)sqlite3_column_double(stmt, column); */
  /* time_t now = time(NULL); */
  /* D1("Cache creation time: %f", created_at); */
  /* D1("Cache  current time: %lld", (long long int) now); */

  /* /\* include case where expire failed and is the default value 0.0 *\/ */
  /* if ( difftime(now, created_at) > options->cache_ttl ){ D2("Cache too old"); return false; } */

  /* valid entry */
  D2("Cache valid");
  return true;
}

int backend_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen)
{
  sqlite3_stmt *stmt = NULL;
  int rc = 1; /* cache miss */
  D2("select username,uid,gecos,inserted from users where uid = %u LIMIT 1", uid);
  sqlite3_prepare_v2(db, "select username,uid,gecos,inserted from users where uid = ?1 LIMIT 1", -1, &stmt, NULL);
  if(stmt == NULL){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return rc; }
  sqlite3_bind_int(stmt, 1, uid);

  /* Is it valid? */
  if(!backend_stmt_valid(stmt, 3)) goto BAILOUT;

  /* Convert to struct PWD */
  if( (rc = _col2txt(stmt, 0, &(result->pw_name), &buffer, &buflen)) ) goto BAILOUT;
  /* if( rc = copy2buffer("x"     , &(result->pw_passwd), &buffer, &buflen) ) goto BAILOUT; */
  result->pw_uid = uid;
  result->pw_gid = options->gid;
  if( (rc = _col2txt(stmt, 2, &(result->pw_gecos), &buffer, &buflen)) ) goto BAILOUT;
  char* homedir = strjoina(options->ega_dir, "/", result->pw_name);
  D3("Username %s [%s]", result->pw_name, homedir);
  if( copy2buffer(homedir, &(result->pw_dir), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }
  if( copy2buffer(options->shell, &(result->pw_shell), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }

  /* success */ rc = 0;
BAILOUT:
  sqlite3_finalize(stmt);
  return rc;
};

int
backend_getpwnam_r(const char* username, struct passwd *result, char* buffer, size_t buflen)
{
  sqlite3_stmt *stmt = NULL;
  int rc = 1; /* cache miss */
  D2("select username,uid,gecos,inserted from users where username = '%s' LIMIT 1", username);
  sqlite3_prepare_v2(db, "select username,uid,gecos,inserted from users where username = ?1 LIMIT 1", -1, &stmt, NULL);
  if(stmt == NULL){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return false; }
  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

  /* Is it valid? */
  if(!backend_stmt_valid(stmt, 3)) goto BAILOUT;

  /* Convert to struct PWD */
  result->pw_name = (char*)username;
  /* if( (rc = _col2txt(stmt, 0, &(result->pw_name), &buffer, &buflen)) ) goto BAILOUT; */
  /* if( (rc = copy2buffer("x"     , &(result->pw_passwd), &buffer, &buflen)) ) goto BAILOUT; */
  result->pw_passwd = options->x;
  if( (rc = _col2uid(stmt, 1, &(result->pw_uid))) ) goto BAILOUT;
  result->pw_gid = options->gid;
  if( (rc = _col2txt(stmt, 2, &(result->pw_gecos), &buffer, &buflen)) ) goto BAILOUT;
  char* homedir = strjoina(options->ega_dir, "/", username);
  D3("Username %s [%s]", username, homedir);
  if( copy2buffer(homedir, &(result->pw_dir), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }
  if( copy2buffer(options->shell, &(result->pw_shell), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }

  /* success */ rc = 0;
BAILOUT:
  sqlite3_finalize(stmt);
  return rc;
}

bool
backend_print_pubkey(const char* username)
{
  sqlite3_stmt *stmt = NULL;
  int found = false; /* cache miss */

  D2("select pubkey,inserted from users where username = %s LIMIT 1", username);
  sqlite3_prepare_v2(db, "select pubkey,inserted from users where username = ?1 LIMIT 1", -1, &stmt, NULL);
  if(stmt == NULL){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return false; }
  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
  if(!backend_stmt_valid(stmt,1)) goto BAILOUT;
  if(sqlite3_column_type(stmt, 0) != SQLITE_TEXT){ D1("The colum 0 is not a string"); goto BAILOUT; }
  const unsigned char* pubkey = sqlite3_column_text(stmt, 0);
  if( !pubkey ){ D1("Memory allocation error"); goto BAILOUT; }
  printf("%s", pubkey);
  found = true; /* success */
BAILOUT:
  sqlite3_finalize(stmt);
  return found;
}


/* Fetch the password hash from the database.
 * Allocates a string into data. You have to clean it when you're done.
 */
int
backend_get_password_hash(const char* username, char** data){
  sqlite3_stmt *stmt = NULL;
  int rc = 1; /* cache miss */
  D2("select pwdh,inserted from users where username = '%s' LIMIT 1", username);
  sqlite3_prepare_v2(db, "select pwdh,inserted from users where username = ?1 LIMIT 1", -1, &stmt, NULL);
  if(stmt == NULL){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return false; }
  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
  if(!backend_stmt_valid(stmt, 1)) goto BAILOUT;
  if(sqlite3_column_type(stmt, 0) != SQLITE_TEXT){ D1("The colum 0 is not a string"); rc = 1; goto BAILOUT; }
  char* s = (char*)sqlite3_column_text(stmt, 0);
  if( s == NULL ){ D1("Memory allocation error"); rc = 1; goto BAILOUT; }
  *data = strdup(s);
  /* success */ rc = 0;
BAILOUT:
  sqlite3_finalize(stmt);
  return rc;
}
