#ifndef NF_HTTP_ANALYZER_H_
#define NF_HTTP_ANALYZER_H_

/*
 * @brief generic string match function
 */
int nf_generic_string_match( const unsigned char * data, const unsigned char * tail, const char * string );

/*
 * @brief GET match macro
 */
#define NF_HTTP_GET_MATCH( data, tail ) nf_generic_string_match( user_data, tail, "GET" )

/*
 * @brief HTTP match macro
 */
#define NF_HTTP_HTTP_MATCH( user_data, tail ) nf_generic_string_match( user_data, tail, "HTTP" )

/*
 * @brief "POST match macro
 */
#define NF_HTTP_POST_MATCH( data, tail ) nf_generic_string_match( user_data, tail, "POST" )

/*
 * @brief "GET...HTTP" matcher function
 */
int nf_http_analyzer_get( const unsigned char *user_data, const unsigned char * tail );

/*
 * @brief "POST...HTTP" matcher function
 */
int nf_http_analyzer_post( const unsigned char *user_data, const unsigned char * tail );

/*
 * @brief analyzer function prototype
 */
typedef int nf_http_analyzer_fn( const unsigned char *user_data, const unsigned char * tail );

/*
 * @brief analyzer steps holder
 */
struct nf_http_analyzer_chain
{
	nf_http_analyzer_fn * analyzer_entry;
};

/*
 * @brief analyzer entry point
 * @returns non-zero if a packet payload matches any http content
 */
int nf_http_analyzer_entry( const unsigned char * user_data, const unsigned char * tail );

#endif
