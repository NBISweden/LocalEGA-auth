#include <curl/curl.h>
#include <jq.h>

#include "utils.h"
#include "backend.h"

struct curl_res_s {
  char *body;
  size_t size;
};

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
get_from_json(jq_state *jq, const char* query, jv json, char** res){
  
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

bool
fetch_from_cega(const char *username)
{
  CURL *curl;
  CURLcode res;
  bool status = false;
  char* endpoint = NULL;
  struct curl_res_s *cres = NULL;
  jv parsed_response;
  jq_state* jq = NULL;
  char *pwd = NULL;
  char *pbk = NULL;
  char *uid = NULL;
  char *gecos = NULL;
  char *shell = NULL;
  
  if(!options->with_cega){ D1("Contacting CentralEGA is disabled"); return false; }

  D1("Contacting cega for user: %s", username);

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

  int rc = 
    get_from_json(jq, options->cega_json_passwd, jv_copy(parsed_response), &pwd   ) +
    get_from_json(jq, options->cega_json_pubkey, jv_copy(parsed_response), &pbk   ) +
    get_from_json(jq, options->cega_json_uid   , jv_copy(parsed_response), &uid   ) +
    get_from_json(jq, options->cega_json_gecos , jv_copy(parsed_response), &gecos ) +
    get_from_json(jq, options->cega_json_shell , jv_copy(parsed_response), &shell ) ;

  if(rc){
    D1("WARNING: CentralEGA JSON received, but parsed with %d invalid quer%s", rc, (rc>1)?"ies":"y");
  } else {
    D1("CentralEGA JSON response correctly parsed");
  }

  jv_free(parsed_response);

  /* Adding to the database, if pwd and pbk are not both null */
  status = (pwd || pbk) && uid && gecos && shell && backend_add_user(username, uid, pwd, pbk, gecos, shell);

BAILOUT:
  D1("User %s%s found in CentralEGA", username, (status)?"":" not");
  if(cres)free(cres);
  if(uid)free(uid); // The others are freed by jv
  jq_teardown(&jq); /* should free pwd and pbk */
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return status;
}
