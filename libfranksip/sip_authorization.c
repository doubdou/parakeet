#include "sip_authorization.h"



struct sip_authorization_t *  sip_authorization_make(apr_pool_t * pool)
{
	// 分配空间. 
	//assert(NULL==*auth);
	struct sip_authorization_t * auth = (struct sip_authorization_t *)apr_pcalloc(pool,sizeof(struct sip_authorization_t));
	assert(auth);
	if (auth)
	{
		auth->pool = pool;
	}

	return auth;
}

struct sip_authorization_t *  sip_authorization_parse(apr_pool_t * pool, const char * buff)
{
	// 成功返回0, 失败返回-1.
	// Authorization: Digest username="13732223846",realm="183.128.154.187",nonce="ec41c20b5ce3e0823c0d59887863f2dc",uri="sip:ec.100meeting.com:5060",response="46309a11059f5e869d9feec7a4005bfa",algorithm=MD5,qop=auth,cnonce="xyz",nc=00000001

	const char * key, *value;
	apr_size_t klen = 0, vlen = 0;
	const char * str;
	struct sip_authorization_t * auth = sip_authorization_make(pool);

	if (NULL == auth)return NULL;

	key = strchr(buff, ' ');
	if (NULL == key)return NULL;

	auth->auth_type = apr_pstrndup(pool, buff, (apr_size_t)(key - buff));
	key++;

	while(key)
	{
		while (' ' == *key)key++;
		str = strchr(key, '=');
		if (0 == str) break;
		klen = (apr_size_t)(str - key);
		str++;
		value = str;
		str = strchr(value, ',');
		if (str)
		{
			vlen = (apr_size_t)(str - value);
			str++;
		}
		else
		{
			vlen = strlen(value);
		}

		if ('"' == *value)
		{
			value++;
			vlen--;
			vlen--;
		}

		if (strncmp(key, "username", klen) == 0) auth->username = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "realm", klen) == 0) auth->realm = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "nonce", klen) == 0) auth->nonce = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "uri", klen) == 0) auth->uri = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "response", klen) == 0) auth->response = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "digest", klen) == 0) auth->digest = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "algorithm", klen) == 0) auth->algorithm = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "cnonce", klen) == 0) auth->cnonce = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "opaque", klen) == 0) auth->opaque = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "nc", klen) == 0) auth->nonce_count = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "qop", klen) == 0) auth->message_qop = apr_pstrndup(pool, value, vlen);

		key = str;

		/****
		if ('=' == *str)
		{
		// 如果字段值中有等于号, 这里判断是有问题的. 例如: uri="sip:10.250.251.32;transport=udp" 这种.
			klen = (apr_size_t)(str - key);
			str++;
			value = str;
		}
		else if (',' == *str || '\0' == *str)
		{
			if (NULL == value)return NULL;

			if ('"' == *value)
			{
				value++;
				vlen = (apr_size_t)(str - value);
				vlen--;
				if ('"' != value[vlen])
					return NULL;
			}
			else
			{
				vlen = (apr_size_t)(str - value);
			}

			if (strncmp(key, "username", klen) == 0) auth->username = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "realm", klen) == 0) auth->realm = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "nonce", klen) == 0) auth->nonce = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "uri", klen) == 0) auth->uri = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "response", klen) == 0) auth->response = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "digest", klen) == 0) auth->digest = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "algorithm", klen) == 0) auth->algorithm = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "cnonce", klen) == 0) auth->cnonce = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "opaque", klen) == 0) auth->opaque = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "nc", klen) == 0) auth->nonce_count = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "qop", klen) == 0) auth->message_qop = apr_pstrndup(pool, value, vlen);

			if ('\0' == *str) break;
			str++;
			while (' ' == *str)str++;
			key = str;
			value = 0;
		}
		else
		{
			str++;
		}
		****/
	}

	return auth;
}

struct sip_authorization_t *  sip_authorization_clone(apr_pool_t * pool, const struct sip_authorization_t * src)
{
	struct sip_authorization_t * tmp = sip_authorization_make(pool);


	if (src->auth_type) tmp->auth_type = apr_pstrdup(pool,src->auth_type);
	if (src->username) tmp->username = apr_pstrdup(pool, src->username);
	if (src->realm) tmp->realm = apr_pstrdup(pool, src->realm);
	if (src->nonce) tmp->nonce = apr_pstrdup(pool, src->nonce);
	if (src->uri) tmp->uri = apr_pstrdup(pool, src->uri);
	if (src->response) tmp->response = apr_pstrdup(pool, src->response);
	if (src->digest) tmp->digest = apr_pstrdup(pool, src->digest);
	if (src->algorithm) tmp->algorithm = apr_pstrdup(pool, src->algorithm);
	if (src->cnonce) tmp->cnonce = apr_pstrdup(pool, src->cnonce);
	if (src->opaque) tmp->opaque = apr_pstrdup(pool, src->opaque);
	if (src->message_qop) tmp->message_qop = apr_pstrdup(pool, src->message_qop);
	if (src->nonce_count) tmp->nonce_count = apr_pstrdup(pool, src->nonce_count);
	if (src->auth_param) tmp->auth_param = apr_pstrdup(pool, src->auth_param);
	
	return tmp;
}

int sip_authorization_to_string(const struct sip_authorization_t * auth, char * buff, int size)
{
	//Authorization: Digest username="8001",realm="00c10b587722fc4ad9a5f58b0c0f37fe",
	//	nonce="00c10b587722fc4ad9a5f58b0c0f37fe",
	//	uri="sip:192.168.1.105;transport=udp",
	//	response="8b4a141de0f69b272605d95434b5ec49",
	//	cnonce="8967fa4d9a33c10f",
	//	nc=00000001,
	//	qop=auth,
	//	algorithm=MD5,
	//	opaque=""
	int len = 0;
	if ( auth == 0 || auth->auth_type == 0 )
		return 0; // 返回长度,不能为-1.

	len = apr_snprintf(buff, (apr_size_t)size, "%s", auth->auth_type);

	if (auth->username)
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), " username=\"%s\"", auth->username);
	if (auth->realm)
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", realm=\"%s\"", auth->realm);
	if (auth->nonce)
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", nonce=\"%s\"", auth->nonce);
	if (auth->uri)
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", uri=\"%s\"", auth->uri);
	if (auth->response)
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", response=\"%s\"", auth->response);
	if (auth->algorithm)
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", algorithm=%s", auth->algorithm);

	if (auth->digest) // 可选
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", digest=\"%s\"", auth->digest);
	if (auth->cnonce) // 可选
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", cnonce=\"%s\"", auth->cnonce);
	if (auth->nonce_count) // 可选
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", nc=%s", auth->nonce_count);
	if (auth->message_qop) // 可选
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", qop=%s", auth->message_qop);
	if (auth->opaque)	// 可选
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), ", opaque=\"%s\"", auth->opaque);
//	buff[len++] = '\r';
//	buff[len++] = '\n';
	return len;
}

int  sip_authorization_set_param(struct sip_authorization_t * auth,
	const char * auth_type,
	const char * username,
	const char * domain,
	const char * nonce,
	const char * alg,
	const char * uri)
{
	auth->auth_type = apr_pstrdup(auth->pool, auth_type);
	auth->username = apr_pstrdup(auth->pool, username);
	auth->realm = apr_pstrdup(auth->pool, domain);
	auth->nonce = apr_pstrdup(auth->pool, nonce);

	if (uri)
	{
		auth->uri = apr_pstrdup(auth->pool, uri);
	}
	else
	{
		auth->uri = apr_psprintf(auth->pool, "sip:%s", domain);
	}

	if (alg)
	{
		auth->algorithm = apr_pstrdup(auth->pool, alg);
	}

	return 0;
}

int  sip_authorization_set_param2(struct sip_authorization_t * auth,
	const char * qop,
	const char * nc,
	const char * opaque,
	const char * cnonce)
{
	assert( qop );
	assert( nc );
	auth->message_qop = apr_pstrdup(auth->pool, qop);
	auth->nonce_count = apr_pstrdup(auth->pool, nc);
	if (opaque) auth->opaque = apr_pstrdup(auth->pool, opaque);
	auth->cnonce = apr_pstrdup(auth->pool, cnonce);

	if ( auth->message_qop == 0 ||
		auth->nonce_count == 0 ||
		//auth->opaque == 0 ||
		auth->cnonce == 0 )
		return -1;
	return 0;
}

int  sip_authorization_set_response(struct sip_authorization_t * auth, const char * response)
{
	auth->response = apr_pstrdup(auth->pool, response);
	if ( 0 == auth->response ) return -1;
	return 0;
}

static void _hash_gigest_calc_ha1(
	const char * pszAlg,
	const char * pszUserName,
	const char * pszRealm,
	const char * pszPassword,
	const char * pszNonce,
	const char * pszCNonce,
	char SessionKey[36]
);

static void _hash_gigest_calc_response(
	//char HA1[36],           /* H(A1) */
	const char * HA1,
	const char * pszNonce,       /* nonce from server */
	const char * pszNonceCount,  /* 8 hex digits */
	const char * pszCNonce,      /* client nonce */
	const char * pszQop,         /* qop-value: "", "auth", "auth-int" */
	const char * pszMethod,      /* method from the request */
	const char * pszDigestUri,   /* requested URL */
	//char HEntity[36],       /* H(entity body) if qop="auth-int" */
	char Response[36]      /* request-digest or response-digest */
);


static void sip_bin2string(unsigned char Bin[], int size, char Hex[])
{
	//将Bin的值转换为字符串。
	//eg:
	// Bin: 4567abcd
	// Hex: "4567abcd"

	unsigned short i;
	unsigned char j;
	char * Ret = Hex;

	for (i = 0; i < size; i++)
	{
		j = (Bin[i] >> 4) & 0xf;
		if (j <= 9) *Ret = (char)(j + '0');
		else *Ret = (char)(j + 'a' - 10);

		Ret++;
		j = Bin[i] & 0xf;
		if (j <= 9) *Ret = (char)(j + '0');
		else *Ret = (char)(j + 'a' - 10);

		Ret++;
	}
	*Ret = '\0';
	//Hex[size<<1] = '\0';
}


void sip_auth_make_response(const struct sip_authorization_t * auth, const char * method, const char * password, char * response)
{
	char HA1[36] = "";

	response[0] = '\0';
	// 如果没有qop指示参数，就不能出现 cnonce值
	// 有qop则必须指定cnonce
	_hash_gigest_calc_ha1(auth->algorithm, auth->username, auth->realm, password, auth->nonce, auth->cnonce, HA1);

	_hash_gigest_calc_response(
		HA1,
		auth->nonce,
		auth->nonce_count,
		auth->cnonce,
		auth->message_qop,
		method,
		auth->uri,
		response);
}

int	sip_authorization_verify(const struct sip_authorization_t * auth, const char * method, const char * password)
{
	char HA1[36] = "";
	char signature[64] = { 0 };

	// 如果没有qop指示参数，就不能出现 cnonce值

	assert(auth);
	assert(auth->nonce);
	assert(auth->nonce_count);
	assert(auth->cnonce);
	assert(auth->uri);
	assert(auth->response);
	assert(method);
	assert(password);

	if (NULL == auth->response)return -1;

	// 有qop则必须指定cnonce
	_hash_gigest_calc_ha1(auth->algorithm, auth->username, auth->realm, password, auth->nonce, auth->cnonce, HA1);

	_hash_gigest_calc_response(
		HA1,
		auth->nonce,
		auth->nonce_count,
		auth->cnonce,
		auth->message_qop,
		method,
		auth->uri,
		signature);

	return apr_strnatcmp(auth->response, signature);
}

static void _hash_gigest_calc_ha1(
	const char * pszAlg,
	const char * pszUserName,
	const char * pszRealm,
	const char * pszPassword,		//1234456
	const char * pszNonce,	//need by MD5-sess  384579384759384795834
	const char * pszCNonce,	//need by MD5-sess 345893495034950345
	char SessionKey[36]
)
{
	// 本函数用于计算 A1, 返回HA1=MD5(A1)
	apr_md5_ctx_t md5ctx;
	unsigned char HA1[16];
	//	char str[200];
	//	int len;

	//	if ( pszUserName == NULL || *pszUserName == '\0' )
	//	{
	//		pszUserName = "anonymous";
	//		pszPassword = "";
	//	}
	if (pszUserName == NULL || pszRealm == NULL || pszPassword == NULL || pszNonce == NULL)
		return;

	// H = MD5
	// H(H(username:realm:password)：nonce：cnonce：H(requestMothod:request-URI))
	//如果没有qop指示参数，就不能出现 cnonce值
	// 计算A1.
	// A1=MD5(username:realm:password)
	/*****
		如果算法（"algorithm"）值是”MD5”或没有指定，则A1是：
　　		A1 = unq(username-value) ":" unq(realm-value) ":" passwd
　　		其中
　　		passwd = < user's password >
	*****/
	apr_md5_init(&md5ctx);

	apr_md5_update(&md5ctx, pszUserName, (apr_size_t)strlen(pszUserName));
	apr_md5_update(&md5ctx, ":", 1);
	apr_md5_update(&md5ctx, pszRealm, (apr_size_t)strlen(pszRealm));
	apr_md5_update(&md5ctx, ":", 1);
	apr_md5_update(&md5ctx, pszPassword, (apr_size_t)strlen(pszPassword));

	//	len = sprintf(str, "%s:%s:%s", pszUserName, pszRealm, pszPassword);
	//	sip_md5_update(&md5ctx, str, len);
	apr_md5_final(HA1, &md5ctx);

	// MD5(A:nonce,cnonce,
	/***
	如果"algorithm"值是"MD5-sess"，则A1只要计算一次，即当客户端发出第一个请求，
	并从服务器收到WWW-鉴别（WWW-Authenticate）质询（challenge）时计算。
	它使用该质询中的服务器的nonce，则用来构建A1的第一个客户端nonce值应为：
　　A1 = H( unq(username-value) ":" unq(realm-value)
　　 ":" passwd )
　　 ":" unq(nonce-value) ":" unq(cnonce-value)
	***/
	if (pszAlg && strcmp(pszAlg, "md5-sess") == 0)
	{
		if (pszCNonce == NULL) return;

		apr_md5_init(&md5ctx);

		apr_md5_update(&md5ctx, (const char*)HA1, 16);
		apr_md5_update(&md5ctx, ":", 1);
		apr_md5_update(&md5ctx, pszNonce, (apr_size_t)strlen(pszNonce));
		apr_md5_update(&md5ctx, ":", 1);
		apr_md5_update(&md5ctx, pszCNonce, (apr_size_t)strlen(pszCNonce));

		//len = sprintf(str, "%s:%s:%s", HA1, pszNonce, pszCNonce);
		//sip_md5_update(&md5ctx, str, len);
		apr_md5_final(HA1, &md5ctx);
	}

	sip_bin2string(HA1, 16, SessionKey);
}

static void _hash_gigest_calc_response(
	//char HA1[36],           /* H(A1) */
	const char * HA1,
	const char * pszNonce,       /* nonce from server */
	const char * pszNonceCount,  /* 8 hex digits */
	const char * pszCNonce,      /* client nonce */
	const char * pszQop,         /* qop-value: "", "auth", "auth-int" */
	const char * pszMethod,      /* method from the request */
	const char * pszDigestUri,   /* requested URL */
	//char HEntity[36],       /* H(entity body) if qop="auth-int" */
	char Response[36]      /* request-digest or response-digest */
)
{
	apr_md5_ctx_t md5ctx;
	unsigned char HA2[16];
	unsigned char RespHash[16];
	char HA2Hex[36];

	if (NULL == pszDigestUri || NULL == pszNonce)
		return;

	// 39dc325c4698a3f1c73b081af6d7e099
	/////////////////////////////////////////////////////////////
	// 计算A2
	// 如果 "qop" 值是 "auth" 或者没给出，则A2：
	// A2=H(requestMothod:request-URI)
	// 如果"qop"值是"auth-int", 则A2：
	// A2 = Method ":" digest-uri-value ":" H(entity-body)

	apr_md5_init(&md5ctx);

	apr_md5_update(&md5ctx, pszMethod, (apr_size_t)strlen(pszMethod));
	apr_md5_update(&md5ctx, ":", 1);
	apr_md5_update(&md5ctx, pszDigestUri, (apr_size_t)strlen(pszDigestUri));

	/*
	if ( pszQop != NULL && strcmp(pszQop, "auth-int") == 0 )
	{
		sip_md5_update(&md5ctx, ":", 1);
		sip_md5_update(&md5ctx, HEntity, 32);
	}
	*/
	apr_md5_final(HA2, &md5ctx);

	/////////////////////////////////////////////////////////////

	sip_bin2string(HA2, 16, HA2Hex);

	/*****
	// 计算Response
	KD(secret, data) = H(concat(secret, ":", data))

	如果”qop”值是"auth" 或"auth-int"：
　　request-digest = <"> < KD ( H(A1), unq(nonce-value)
　　 ":" nc-value
　　 ":" unq(cnonce-value)
　　 ":" unq(qop-value)
　　 ":" H(A2)
　　 ) <">

	如果”qop”指示没有给出（与RFC2069保持兼容性）：
　　request-digest =<"> < KD ( H(A1), unq(nonce-value) ":" H(A2)　) <">
	****/

	// calculate response
	// MD5(A:nonce:cnonce:B)

	apr_md5_init(&md5ctx);
	apr_md5_update(&md5ctx, HA1, 32);
	apr_md5_update(&md5ctx, ":", 1);
	apr_md5_update(&md5ctx, pszNonce, (apr_size_t)strlen(pszNonce));

	if (pszQop != NULL && strcmp(pszQop, "auth") == 0)
	{
		if (pszCNonce == NULL) return;

		if (pszNonceCount == NULL) pszNonceCount = "00000001";

		apr_md5_update(&md5ctx, ":", 1);
		apr_md5_update(&md5ctx, pszNonceCount, (apr_size_t)strlen(pszNonceCount));
		apr_md5_update(&md5ctx, ":", 1);
		apr_md5_update(&md5ctx, pszCNonce, (apr_size_t)strlen(pszCNonce));
		apr_md5_update(&md5ctx, ":", 1);
		apr_md5_update(&md5ctx, pszQop, (apr_size_t)strlen(pszQop));
	}

	apr_md5_update(&md5ctx, ":", 1);
	apr_md5_update(&md5ctx, (char*)HA2Hex, 32);

	apr_md5_final(RespHash, &md5ctx);
	sip_bin2string(RespHash, 16, Response);
}

void sip_auth_convert_callid2nonce(const char * callid, char nonce[36])
{
	unsigned char digest[APR_MD5_DIGESTSIZE];
	apr_md5(digest, callid, strlen(callid));
	sip_bin2string(digest, 16, nonce);
}
