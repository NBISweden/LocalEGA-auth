#include <string.h>

#include "utils.h"
#include "config.h"
#include "json.h"

#define CEGA_JSON_PREFIX_DELIM "."

/* Will search for options->cega_json_prefix first, and then those exact ones */
#define CEGA_JSON_USER  "username"
#define CEGA_JSON_UID   "uid"
#define CEGA_JSON_PWD   "passwordHash"
#define CEGA_JSON_PBK   "sshPublicKey"
#define CEGA_JSON_GECOS "gecos"

#ifdef DEBUG
#define TYPE2STR(t) (((t) == JSMN_OBJECT)   ? "Object":    \
                     ((t) == JSMN_ARRAY)    ? "Array":     \
                     ((t) == JSMN_STRING)   ? "String":    \
                     ((t) == JSMN_PRIMITIVE)? "Primitive": \
                                              "Undefined")
#endif

static int
get_size(jsmntok_t *t){
  int i, j;
  if (t->type == JSMN_PRIMITIVE || t->type == JSMN_STRING) {
    if(t->size > 0) return get_size(t+1)+1;
    return 1;
  } else if (t->type == JSMN_OBJECT || t->type == JSMN_ARRAY) {
    j = 0;
    for (i = 0; i < t->size; i++) { j += get_size(t+1+j); }
    return j+1;
  } else {
    D1("get_size: weird type %s", TYPE2STR(t->type));
    return 1000000;
  }
}

#define KEYEQ(json, t, s) ((int)strlen(s) == ((t)->end - (t)->start)) && strncmp((json) + (t)->start, s, (t)->end - (t)->start) == 0

int
parse_json(const char* json, int jsonlen,
	   char** username, char** pwd, char** pbk, char** gecos, int* uid)
{
  jsmn_parser jsonparser; /* on the stack */
  jsmntok_t *tokens = NULL; /* array of tokens */
  char* prefix = NULL;
  size_t size_guess = 11; /* 5*2 (key:value) + 1(object) */
  int r, rc=1;

REALLOC:
  /* Initialize parser (for every guess) */
  jsmn_init(&jsonparser);
  D2("Guessing with %zu tokens", size_guess);
  if(tokens)free(tokens);
  tokens = malloc(sizeof(jsmntok_t) * size_guess);
  if (tokens == NULL) { D1("memory allocation error"); goto BAILOUT; }
  r = jsmn_parse(&jsonparser, json, jsonlen, tokens, size_guess);
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
  if( tokens->type != JSMN_OBJECT ){ D1("JSON object expected"); rc = 1; goto BAILOUT; }
  if( r<7 ){ D1("We should get at least 7 tokens"); rc = 1; goto BAILOUT; }

  /* Find root token given the CentralEGA prefix */
  prefix = strdup(options->cega_json_prefix); /* strtok modifies the str, so making copy */
  if (prefix == NULL) { D1("memory allocation error"); goto BAILOUT; }
  char* prefix2 = prefix; /* Trick from https://stackoverflow.com/a/28686287/6401565 */
  const char *part = strtok(prefix2, CEGA_JSON_PREFIX_DELIM);
   
  /* walk through other tokens */
  jsmntok_t *t = tokens; /* use a sentinel and move inside the object */
  int j=0, k=0;
  while( j<r && part != NULL ) {
    t++;
    D3("Finding '%s' in JSON", part);
    
inspect:
    if( KEYEQ(json, t, part) ) goto found;
    D3("nope... %.*s [%d items]", t->end-t->start, json + t->start, t->size);
    k=get_size(t+1)+1;
    j+=k;
    if( j>=r ){ D1("We have exhausted all the tokens"); rc = 1; goto BAILOUT; }
    t+=k;
    goto inspect;

found:
    D3( "%s found", part );
    t++; /* next should be the root object or array */

    /* In case the root is an array, fetch the first element */
    if( t->type == JSMN_ARRAY ){ t++; }

    /* We should now point to the root object */
    if( t->type != JSMN_OBJECT ){ D1("JSON object expected, but got %s", TYPE2STR(t->type)); rc = 1; goto BAILOUT; }

    part = strtok(NULL, CEGA_JSON_PREFIX_DELIM);
  }

  if( j>=r ){ D1("We have exhausted all the tokens"); rc = 1; goto BAILOUT; }

  D1("ROOT %.*s [%d items]", t->end-t->start, json + t->start, t->size);

  int max = t->size;
  /* if( max<5 ){ D1("Invalid JSON"); rc = 1; goto BAILOUT; } */
  int i;
  t++; /* move inside the root */
  rc = 0; /* assume success */
  for (i = 0; i < max; i++, t+=t->size+1) {

    if(t->type == JSMN_STRING){

      if( KEYEQ(json, t, CEGA_JSON_USER) ){
	t+=t->size; /* get to the value */
	if(*username){ D3("Strange! I already have username"); continue; }
	*username = strndup(json + t->start, t->end-t->start);
      } else if( KEYEQ(json, t, CEGA_JSON_PWD) ){
	t+=t->size; /* get to the value */
	if(*pwd){ D3("Strange! I already have pwd"); continue; }
	*pwd = strndup(json + t->start, t->end-t->start);
      } else if( KEYEQ(json, t, CEGA_JSON_GECOS) ){
	t+=t->size; /* get to the value */
	if(*gecos){ D3("Strange! I already have gecos"); continue; }
	*gecos = strndup(json + t->start, t->end-t->start);
      } else if( KEYEQ(json, t, CEGA_JSON_PBK) ){
	t+=t->size; /* get to the value */
	if(*pbk){ D3("Strange! I already have pbk"); continue; }
	*pbk = strndup(json + t->start, t->end-t->start);
      } else if( KEYEQ(json, t, CEGA_JSON_UID) ){
	t+=t->size; /* get to the value */
	char* cend;
	*uid = strtol(json + t->start, (char**)&cend, 10); /* reuse cend above */
	if( (cend != (json + t->end)) ) *uid=-1; /* error when cend does not point to end+1 */
      } else {
	D3("Unexpected key: %.*s with %d items", t->end-t->start, json + t->start, t->size);
	t+=t->size; /* get to the value */
	D3("of type %s with %d items", TYPE2STR(t->type), t->size);
      }
    } else {
      D2("Not a string token");
      rc++;
    }
  }

#ifdef DEBUG
  if(rc) D1("%d errors while parsing the root object", rc);
#endif

BAILOUT:
  if(tokens){ D3("Freeing tokens at %p", tokens); free(tokens); }
  if(prefix){ D3("Freeing prefix at %p", prefix ); free(prefix); }
  return rc;
}
