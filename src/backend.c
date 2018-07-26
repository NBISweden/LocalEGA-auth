#include <string.h>
#include <time.h>
#include <sqlite3.h>

#include "utils.h"
#include "backend.h"


/* DB schema */
#define EGA_SCHEMA "CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE PRIMARY KEY ON CONFLICT REPLACE, \
                                                      uid      INTEGER,                 \
                    		 		      pwdh     TEXT,	                \
		                    		      pubkey   TEXT,	                \
				                      gecos    TEXT,                    \
                    				      inserted REAL DEFAULT (strftime('%s','now'))) WITHOUT ROWID;"

/* WITHOUT ROWID works only from 3.8.2 */

/* columns */
#define EGA_USERNAME 0
#define EGA_UID      1
#define EGA_PASSWD_H 2
#define EGA_PUBKEY   3
#define EGA_GECOS    4
#define EGA_CREATED  5

static sqlite3* db = NULL;

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
  D3("********** CONSTRUCTOR");
  backend_open();
}

__attribute__((destructor))
static void
destroy(void)
{
  D3("********** DESTRUCTOR");
  backend_close(); 
}

inline bool
backend_opened(void)
{
  return db != NULL && sqlite3_errcode(db) == SQLITE_OK;
}

void
backend_open(void)
{
  loadconfig();
  if( !config_loaded() ) return;
  if( backend_opened() ) return;

  D1("Connection to: %s", options->db_connstr);
  sqlite3_open(options->db_connstr, &db);
  if (db == NULL){ D1("Failed to allocate database handle"); return; }
  D3("DB Connection: %p", db);
  
  if( sqlite3_errcode(db) != SQLITE_OK) {
    D1("Failed to open DB: [%d] %s", sqlite3_extended_errcode(db), sqlite3_errstr(sqlite3_extended_errcode(db)));
    return;
  }
  
  /* create table */
  D2("Creating the database schema");
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, EGA_SCHEMA, -1, &stmt, NULL);
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
_col2txt(sqlite3_stmt **stmt, int col, char** data)
{
  D3("Convert column %d to txt", col);
  if(sqlite3_column_type(*stmt, col) != SQLITE_TEXT){ D1("The colum %d is not a string", col); return 1; }
  *data = (char*)sqlite3_column_text(*stmt, col);
  if( *data == NULL ){ D1("Memory allocation error"); return 1; }
  return 0;
}

static inline int
_col2uid(sqlite3_stmt **stmt, int col, uid_t *uid)
{
  D3("Convert column %d to uid", col);
  if(sqlite3_column_type(*stmt, col) != SQLITE_INTEGER){ D1("The colum %d is not a int", col); return 1; }
  *uid = (uid_t)sqlite3_column_int(*stmt, col);
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
static int
stmt2pwd(sqlite3_stmt** stmt, struct passwd *result, char *buffer, size_t buflen)
{
  char* username = NULL;
  char* gecos = NULL;
  uid_t uid = NULL; // unsigned int

  D2("Convert SQL result to PASSWD result");

  int errors = _col2txt(stmt, EGA_USERNAME, &username) +
               _col2txt(stmt, EGA_GECOS   , &gecos   ) +
               _col2uid(stmt, EGA_UID     , &uid     ) ;
               
  if( errors > 0 ){ D1("Found %d errors", errors); return 2; }
  if( uid <= options->range_shift ){ D1("User id too low: %u", uid); return 2; }
  D3("User id: %u", uid);

  char* homedir = strjoina(options->ega_dir, "/", username);
  D3("Username %s [%s]", username, homedir);

  if( copy2buffer(username, &(result->pw_name)  , &buffer, &buflen) < 0 ) { return -1; }
  if( copy2buffer("x"     , &(result->pw_passwd), &buffer, &buflen) < 0 ) { return -1; }
  if( copy2buffer(gecos   , &(result->pw_gecos) , &buffer, &buflen) < 0 ) { return -1; }
  if( copy2buffer(homedir , &(result->pw_dir)   , &buffer, &buflen) < 0 ) { return -1; }
  if( copy2buffer(options->shell, &(result->pw_shell) , &buffer, &buflen) < 0 ) { return -1; }
  result->pw_uid = uid;
  result->pw_gid = options->ega_gid;
  return 0;
}

/*
 * Check the cache entry not expired
 */
static inline bool
backend_stmt_valid(sqlite3_stmt** stmt)
{
  /* cache miss */
  if(sqlite3_step(*stmt) != SQLITE_ROW) { D2("No SQL row"); return false; }

  /* checking expiration */
  if(sqlite3_column_type(*stmt, EGA_CREATED) != SQLITE_FLOAT){ D1("The expiration is not a float"); return false; }
  double created_at = (time_t)sqlite3_column_double(*stmt, EGA_CREATED);
  time_t now = time(NULL);
  if ( difftime(now, created_at) > options->cache_ttl ){
    /* include case where expire failed and is the default value 0.0 */
    D2("Cache too old"); return false;
  }

  D1("Cache creation time: %f", created_at);
  D1("Cache  current time: %lld", (long long int) now);

  /* valid entry */
  D2("Cache valid");
  return true;
}

static inline bool
backend_get_uid(uid_t uid, sqlite3_stmt** stmt){
  D2("select * from users where uid = %u LIMIT 1", uid);
  sqlite3_prepare_v2(db, "select * from users where uid = ?1 LIMIT 1", -1, stmt, NULL);
  if(*stmt == NULL){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return false; }
  sqlite3_bind_int(*stmt, 1, uid);
  return backend_stmt_valid(stmt);
}

int backend_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen)
{
  sqlite3_stmt *stmt = NULL;
  int rc = 1; /* cache miss */
  if(!backend_get_uid(uid, &stmt)) goto BAILOUT;
  rc = stmt2pwd(&stmt, result, buffer, buflen);
#ifdef DEBUG
  if(rc == -1) D1("Buffer too small");
  if(rc > 0) D1("Statement error");
#endif
BAILOUT:
  sqlite3_finalize(stmt);
  return rc;
};

bool
backend_uid_found(uid_t uid)
{
  sqlite3_stmt *stmt = NULL;
  bool success = backend_get_uid(uid, &stmt);
  sqlite3_finalize(stmt);
  return success;
}

static inline bool
backend_get_username(const char* username, sqlite3_stmt** stmt){
  D2("select * from users where username = %s LIMIT 1", username);
  sqlite3_prepare_v2(db, "select * from users where username = ?1 LIMIT 1", -1, stmt, NULL);
  if(*stmt == NULL){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return false; }
  sqlite3_bind_text(*stmt, 1, username, -1, SQLITE_STATIC);
  return backend_stmt_valid(stmt);
}

int
backend_getpwnam_r(const char* username, struct passwd *result, char* buffer, size_t buflen)
{
  sqlite3_stmt *stmt = NULL;
  int rc = 1; /* cache miss */
  if(!backend_get_username(username, &stmt)) goto BAILOUT;
  rc = stmt2pwd(&stmt, result, buffer, buflen);
#ifdef DEBUG
  if(rc == -1) D1("Buffer too small");
  if(rc > 0) D1("Statement error");
#endif
BAILOUT:
  sqlite3_finalize(stmt);
  return rc;
}

bool
backend_username_found(const char* username)
{
  sqlite3_stmt *stmt = NULL;
  bool success = backend_get_username(username, &stmt);
  sqlite3_finalize(stmt);
  return success;
}

int
backend_get_password_hash(const char* username, char** data){
  sqlite3_stmt *stmt = NULL;
  int rc = 0;
  if(backend_get_username(username, &stmt))
    rc = _col2txt(&stmt, EGA_PASSWD_H, data);
  *data = strdup(*data);
  sqlite3_finalize(stmt);
  return rc;
}

int
backend_get_pubkey(const char* username, char** data){
  sqlite3_stmt *stmt = NULL;
  int rc = 0;
  if(backend_get_username(username, &stmt))
    rc = _col2txt(&stmt, EGA_PUBKEY, data);
  *data = strdup(*data);
  sqlite3_finalize(stmt);
  return rc;
}
