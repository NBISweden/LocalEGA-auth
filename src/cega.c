#include <curl/curl.h>
#include <jq.h>
#include <pwd.h>

#include "utils.h"
#include "backend.h"
#include "cega.h"

/* Will be appended to options->cega_json_prefix */
#define CEGA_JSON_UID   ".uid"
#define CEGA_JSON_PWD   ".password_hash"
#define CEGA_JSON_PBK   ".pubkey"
#define CEGA_JSON_GECOS ".gecos"

struct curl_res_s {
  char *body;
  size_t size;
};

static inline int
uidtostr(const int uid, char** data)
{
  int uid_length = snprintf( NULL, 0, "%d", uid); // how many character do we need
  D3("Value %d needs %d characters", uid, uid_length);
  if (uid_length < 0) { D2("Unable to convert the user id to a number"); return -1; }
  *data = malloc( uid_length + 1 ); // for \0
  memset(*data, '\0', uid_length + 1);
  if (snprintf( *data, uid_length + 1, "%d", uid ) < 0) { D2("Unable to convert the user id to a number"); return -1; }
  return 0;
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

static int
get_from_json(jq_state *jq, const char* query_end, jv json, char** res){

  char* query = strjoina(options->cega_json_prefix, query_end);
  D3("Processing query: %s", query);

  if (!jq_compile(jq, query)){ D3("Invalid query"); return 1; }

  jq_start(jq, json, 0); // no flags
  jv result = jq_next(jq);
  if(jv_is_valid(result)){ // no consume

    switch(jv_get_kind(result)) { // no consume
 
    case JV_KIND_STRING:
	D3("Processing a string");
	*res = (char*)jv_string_value(result); // consumed
	break;

    case JV_KIND_NUMBER:
	D3("Processing a number");
	int uid = jv_number_value(result); // consumed
	uidtostr( uid, res );
	break;

    default:
      D3("Valid result but not a string, nor a number");
      //jv_dump(result, 0);
      jv_free(result);
    }
  }
  D3("Valid result: %s", *res);
  return 0;
}

int
cega_get_username(const char *username,
		  int (*cb)(uid_t, char*, char*, char*))
{
  int rc = 1; /* error */
  CURL *curl;
  CURLcode res;
  char* endpoint = NULL;
  struct curl_res_s *cres = NULL;
  jv parsed_response;
  jq_state* jq = NULL;
  char *pwd = NULL;
  char *pbk = NULL;
  char *gecos = NULL;
  _cleanup_str_ char *uid = NULL; /* the others are cleaned by jv */
  
  D1("Contacting CentralEGA for user: %s", username);

  if(!options->cega_creds){ D2("Empty CEGA credentials"); return 1; /* early quit */ }

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();

  if(!curl) { D2("libcurl init failed"); goto BAILOUT; }

  /* Formatting the endpoint */
  endpoint = strjoina(options->cega_endpoint, username);
  D2("CEGA endpoint: %s", endpoint);

  /* Preparing CURL */
  D2("Preparing CURL");
  cres = (struct curl_res_s*)malloc(sizeof(struct curl_res_s));
  cres->body = NULL;
  cres->size = 0;

  curl_easy_setopt(curl, CURLOPT_NOPROGRESS    , 1L               ); /* shut off the progress meter */
  curl_easy_setopt(curl, CURLOPT_URL           , endpoint         );
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION , curl_callback    );
  curl_easy_setopt(curl, CURLOPT_WRITEDATA     , (void*)cres      );
  curl_easy_setopt(curl, CURLOPT_FAILONERROR   , 1L               ); /* when not 200 */
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH      , CURLAUTH_BASIC);
  curl_easy_setopt(curl, CURLOPT_USERPWD       , options->cega_creds);
  /* curl_easy_setopt(curl, CURLOPT_SSLCERT      , options->ssl_cert); */
  /* curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE  , "PEM"            ); */

#ifdef DEBUG
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  D2("CEGA Request done");
  if(res != CURLE_OK){ D2("curl_easy_perform() failed: %s", curl_easy_strerror(res)); goto BAILOUT; }

  D2("Parsing the JSON response");
  parsed_response = jv_parse(cres->body);

  if (!jv_is_valid(parsed_response)) { D2("Invalid response"); goto BAILOUT; }

  /* Preparing the queries */
  jq = jq_init();
  if (jq == NULL) { D2("jq error with malloc"); goto BAILOUT; }

  rc = 
    get_from_json(jq, CEGA_JSON_PWD  , jv_copy(parsed_response), &pwd   ) +
    get_from_json(jq, CEGA_JSON_PBK  , jv_copy(parsed_response), &pbk   ) +
    get_from_json(jq, CEGA_JSON_UID  , jv_copy(parsed_response), &uid   ) +
    get_from_json(jq, CEGA_JSON_GECOS, jv_copy(parsed_response), &gecos ) ;

  if(rc){
    D1("WARNING: CentralEGA JSON received, but parsed with %d invalid quer%s", rc, (rc>1)?"ies":"y");
  } else {
    D1("CentralEGA JSON response correctly parsed");
  }

  jv_free(parsed_response);

  /* conversion to uid_t */
  uid_t ega_uid;
  if(!uid || rc){ D1("Could not load the user id of '%s'", username); goto BAILOUT; }
  if( !sscanf(uid, "%u" , &ega_uid) ){ D1("Could not convert the user id of '%s' to an int", username); rc = 1; goto BAILOUT; }
  ega_uid += options->uid_shift;
  D2("%s has user id %d", username, ega_uid);

  /* Checking the data */
  if( (!pwd && !pbk) || !gecos || ega_uid <= options->uid_shift ){ rc = 1; goto BAILOUT; }

  /* What to do with the data */
  rc = cb(ega_uid, pwd, pbk, gecos);

BAILOUT:
  if(cres)free(cres);
  jq_teardown(&jq); /* should free pwd and pbk */
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return rc;
}

