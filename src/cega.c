#include <curl/curl.h>
#include <pwd.h>

#include "jsmn/jsmn.h"

#include "utils.h"
#include "backend.h"
#include "cega.h"

/* Will be appended to options->cega_json_prefix */
#define CEGA_JSON_USER  "username"
#define CEGA_JSON_USER_len  8
#define CEGA_JSON_UID   "uid"
#define CEGA_JSON_UID_len 3
#define CEGA_JSON_PWD   "password_hash"
#define CEGA_JSON_PWD_len 13
#define CEGA_JSON_PBK   "pubkey"
#define CEGA_JSON_PBK_len 6
#define CEGA_JSON_GECOS "gecos"
#define CEGA_JSON_GECOS_len 5

#define CEGA_JSON_PREFIX_DELIM "."

struct curl_res_s {
  char *body;
  size_t size;
};

#define KEYEQ(json, t, s) ((int)strlen(s) == (t)->end - (t)->start && strncmp((json) + (t)->start, s, (t)->end - (t)->start) == 0)
#define TYPE2STR(t) (((t) == JSMN_OBJECT)   ? "Object":    \
                     ((t) == JSMN_ARRAY)    ? "Array":     \
                     ((t) == JSMN_STRING)   ? "String":    \
                     ((t) == JSMN_PRIMITIVE)? "Primitive": \
                                              "Undefined")

static int
get_size(jsmntok_t *t){
  int i, j;
  if (t->type == JSMN_PRIMITIVE || t->type == JSMN_STRING) {
    if(t->size > 0) return get_size(t+1)+1;
    return 1;
  } else if (t->type == JSMN_OBJECT || t->type == JSMN_ARRAY) {
    j = 0;
    for (i = 0; i < t->size; i++) { j += get_size(t+1+i); }
    return j+1;
  } else {
    D1("get_size: weird type %s", TYPE2STR(t->type));
    return 0;
  }
}

/* callback for curl fetch */
size_t
curl_callback (void* contents, size_t size, size_t nmemb, void* userdata) {
  const size_t realsize = size * nmemb;                      /* calculate buffer size */
  struct curl_res_s *cres = (struct curl_res_s*) userdata;   /* cast pointer to fetch struct */

  /* expand buffer */
  cres->body = (char *) realloc(cres->body, cres->size + realsize + 1);

  /* check buffer */
  if (cres->body == NULL) { D2("ERROR: Failed to expand buffer in curl_callback"); return -1; }

  /* copy contents to buffer */
  memcpy(&(cres->body[cres->size]), contents, realsize);
  cres->size += realsize;
  cres->body[cres->size] = '\0';

  return realsize;
}

int
cega_resolve(const char *endpoint,
	     int (*cb)(char*, uid_t, char*, char*, char*))
{
  int rc = 1; /* error */
  struct curl_res_s* cres = NULL;
  CURL* curl = NULL;
  jsmn_parser jsonparser; /* on the stack */
  jsmntok_t *tokens = NULL; /* array of tokens */
  _cleanup_str_ char* prefix = NULL;
  char *username = NULL;
  char *pwd = NULL;
  char *pbk = NULL;
  char *gecos = NULL;
  int uid = -1;

  D1("Contacting %s", endpoint);

  /* Preparing cURL */
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();

  if(!curl) { D2("libcurl init failed"); goto BAILOUT; }

  /* Preparing result */
  cres = (struct curl_res_s*)malloc(sizeof(struct curl_res_s));
  if(!cres){ D1("memory allocation failure for the cURL result"); goto BAILOUT; }
  cres->body = NULL;
  cres->size = 0;

  /* Preparing the request */
  curl_easy_setopt(curl, CURLOPT_URL           , endpoint         );
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION , curl_callback    );
  curl_easy_setopt(curl, CURLOPT_WRITEDATA     , (void*)cres      );
  curl_easy_setopt(curl, CURLOPT_FAILONERROR   , 1L               ); /* when not 200 */
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH      , CURLAUTH_BASIC);
  curl_easy_setopt(curl, CURLOPT_USERPWD       , options->cega_creds);
  /* curl_easy_setopt(curl, CURLOPT_NOPROGRESS    , 0L               ); */ /* enable progress meter */
  /* curl_easy_setopt(curl, CURLOPT_SSLCERT      , options->ssl_cert); */
  /* curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE  , "PEM"            ); */

#ifdef DEBUG
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

  /* Perform the request */
  CURLcode res = curl_easy_perform(curl);
  if(res != CURLE_OK){ D2("curl_easy_perform() failed: %s", curl_easy_strerror(res)); goto BAILOUT; }

  /* Successful cURL */
  D2("Parsing the JSON response");

  D1("JSON string [size %zu]: %s", cres->size, cres->body);

  size_t size_guess = 11; /* 5*2 (key:value) + 1(object) */
  int r;

REALLOC:
  /* Initialize parser (for every guess) */
  jsmn_init(&jsonparser);
  D2("Guessing with %zu tokens", size_guess);
  if(tokens)free(tokens);
  tokens = malloc(sizeof(jsmntok_t) * size_guess);
  if (tokens == NULL) { D1("memory allocation error"); goto BAILOUT; }
  r = jsmn_parse(&jsonparser, cres->body, cres->size, tokens, size_guess);
  if (r < 0) { /* error */
    D2("JSON parsing error: %s", (r == JSMN_ERROR_INVAL)? "JSON string is corrupted" :
                                 (r == JSMN_ERROR_PART) ? "Incomplete JSON string":
                                 (r == JSMN_ERROR_NOMEM)? "Not enough space in token array":
                                                          "Unknown error");
    if (r == JSMN_ERROR_NOMEM) {
      size_guess = size_guess * 2; /* double it */
      goto REALLOC;
    }
    goto BAILOUT;
  }

  /* Valid response */
  D3("%d tokens found", r);

  if( tokens->type != JSMN_OBJECT ){ D1("JSON object expected"); goto BAILOUT; }

  /* Find root token given the CentralEGA prefix */
  jsmntok_t *t = tokens;
  prefix = strdup(options->cega_json_prefix); /* strtok modifies the str, so making copy */
  const char *part = strtok(prefix, CEGA_JSON_PREFIX_DELIM);
   
  /* walk through other tokens */
  int j = r;
  while( j>0 && part != NULL ) {
    t++;
    D3( "Finding part \"%s\" in JSON", part );
    
    while(j>0 && !KEYEQ(cres->body, t, part)){
      D3("nope... %.*s [%d items]", t->end-t->start,cres->body + t->start, t->size);
      int k=get_size(t+1)+1;
      j-=k;
      t+=k;
    }

    if( j<=0 ){ D1("We have exhausted all the tokens"); rc = 1; goto BAILOUT; }

    D3( "%s found", part );
    t++; /* next */
    if( t->type != JSMN_OBJECT ){ D1("JSON object expected"); rc = 1; goto BAILOUT; }
    
    part = strtok(NULL, CEGA_JSON_PREFIX_DELIM);
  }
   
  if( j<=0 ){ D1("We have exhausted all the tokens"); rc = 1; goto BAILOUT; }

  D1("ROOT %.*s [%d items]", t->end-t->start,cres->body + t->start, t->size);

  int max = t->size;
  /* if( max<5 ){ D1("Invalid JSON"); rc = 1; goto BAILOUT; } */
  int i;
  t++; /* next token */
  rc = 0;
  for (i = 0; i < max; i++, t+=t->size+1) {

    if(t->type == JSMN_STRING){

      if( KEYEQ(cres->body, t, CEGA_JSON_USER) ){
	t+=t->size; /* get to the value */
	username = strndup(cres->body + t->start, t->end-t->start);
      } else if( KEYEQ(cres->body, t, CEGA_JSON_PWD) ){
	t+=t->size; /* get to the value */
	pwd = strndup(cres->body + t->start, t->end-t->start);
      } else if( KEYEQ(cres->body, t, CEGA_JSON_GECOS) ){
	t+=t->size; /* get to the value */
	gecos = strndup(cres->body + t->start, t->end-t->start);
      } else if( KEYEQ(cres->body, t, CEGA_JSON_PBK) ){
	t+=t->size; /* get to the value */
	pbk = strndup(cres->body + t->start, t->end-t->start);
      } else if( KEYEQ(cres->body, t, CEGA_JSON_UID) ){
	t+=t->size; /* get to the value */
	char* cend;
	uid = strtol(cres->body + t->start, (char**)&cend, 10); /* reuse cend above */
	if( (cend != (cres->body + t->end)) ) uid=-1; /* error when cend does not point to end+1 */
      } else {
	D3("Unexpected key: %.*s with %d items", t->end-t->start, cres->body + t->start, t->size);
	t+=t->size; /* get to the value */
	D3("of type %s with %d items", TYPE2STR(t->type), t->size);
      }
    } else {
      D2("Not a string token");
      rc++;
    }
  }

  if(rc) { D1("%d errors while parsing the root object", rc); goto BAILOUT; }

  /* Checking the data */
  if( !pwd && !pbk ) rc++;
  if( uid <= 0 ) rc++;
  /* if( !gecos ) rc++; */
  if( !gecos ) gecos = strdup("LocalEGA User");

  if(rc) { D1("We found %d errors", rc); }
  else { rc = cb(username, (uid_t)(uid + options->uid_shift), pwd, pbk, gecos); }

BAILOUT:
  if(cres)free(cres);
  if(tokens)free(tokens);
  if(username)free(username);
  if(pwd)free(pwd);
  if(pbk)free(pbk);
  if(gecos)free(gecos);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return rc;
}
