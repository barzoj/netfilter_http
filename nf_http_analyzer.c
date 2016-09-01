#include "nf_http_analyzer.h"
#include <linux/textsearch.h>

//analyzer chain init
//TODO: implement additional analyzers and put them into chain
struct nf_http_analyzer_chain analyzer_chain[] = {
		{ .analyzer_entry = nf_http_analyzer_get },
		{ .analyzer_entry = nf_http_analyzer_post },
		{ .analyzer_entry = NULL }
};

int nf_generic_string_match( const unsigned char *user_data, const unsigned char * tail, const char * string)
{
	int pos = UINT_MAX;
	struct ts_config *conf;
	struct ts_state state;
	if (user_data == NULL || tail == NULL ||
			string == NULL || user_data >= tail )
		return pos;

	conf = textsearch_prepare("kmp", string, strlen(string),
			GFP_KERNEL, TS_AUTOLOAD);

	if (IS_ERR(conf))
		goto err;

	pos = textsearch_find_continuous(conf, &state, user_data, tail-user_data);

err:
 	 textsearch_destroy(conf);
 	 return pos;
}


int nf_http_analyzer_get( const unsigned char *user_data, const unsigned char * tail)
{
	int get_result = NF_HTTP_GET_MATCH(user_data, tail);
	return get_result == UINT_MAX ? get_result : NF_HTTP_HTTP_MATCH(user_data + get_result, tail);
}

int nf_http_analyzer_post( const unsigned char *user_data, const unsigned char * tail )
{
	int get_result = NF_HTTP_POST_MATCH(user_data, tail);
	return get_result == UINT_MAX ? get_result : NF_HTTP_HTTP_MATCH(user_data + get_result, tail);
}

int nf_http_analyzer_entry( const unsigned char * user_data, const unsigned char * tail )
{
	nf_http_analyzer_fn * fn;
	int fn_result = UINT_MAX;
	int i = 0;

	while ( 42 )
	{
		fn = analyzer_chain[i].analyzer_entry;

		if ( fn == NULL )
			break;

		fn_result = fn( user_data, tail );

		if ( fn_result == UINT_MAX )
		{
			i++;
			continue;
		}
		break;
	}
	return fn_result;
}
