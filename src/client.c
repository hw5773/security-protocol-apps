#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <assert.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <app_debug.h>
#include <app_defines.h>

typedef struct arg_st
{
  const char *host;
  int port;
  int protocol;
  
  void *ctx;
} arg_t;

void *run(void *data);
void* init_client_ctx(int library, int protocol);
void free_client_ctx(int library, int protocol, void *ctx);

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -a, --address     Server Host Name");
  emsg("  -p, --port        Server Port Number");
  emsg("  -o, --openssl     Use the OpenSSL library");
  emsg("  -w, --wolfssl     Use the WolfSSL library");
  emsg("  -d, --dtls        Run DTLS 1.3 Protocol");
  emsg("  -q, --quic        Run QUIC Protocol");
  emsg("  -t, --tls         Run TLS 1.3 Protocol");
  exit(1);
}

int dtype;
int main(int argc, char *argv[])
{   
  const char *pname, *host, *opt;
	int c, rc, port, dtls_enabled, quic_enabled, tls_enabled, library, protocol, tmp;
  int openssl_used, wolfssl_used;
  void *ctx;
  arg_t *arg;

  dtype = APP_DEBUG_CLIENT;
  pname = argv[0];
  host = DEFAULT_HOST_NAME;
  port = DEFAULT_PORT_NUMBER;
  dtls_enabled = 0;
  quic_enabled = 0;
  tls_enabled = 0;
  library = 0;
  protocol = 0;

  while (1)
  {
    int opt_idx = 0;
    static struct option long_options[] = {
      {"host", required_argument, 0, 'a'},
      {"port", required_argument, 0, 'p'},
      {"dtls", no_argument, 0, 'd'},
      {"quic", no_argument, 0, 'q'},
      {"tls", no_argument, 0, 't'},
      {"openssl", no_argument, 0, 'o'},
      {"wolfssl", no_argument, 0, 'w'},
      {0, 0, 0, 0}
    };

    opt = "a:p:dqtow0";

    c = getopt_long(argc, argv, opt, long_options, &opt_idx);

    if (c == -1)
      break;

    switch (c)
    {
      case 'a':
        host = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'd':
        dtls_enabled = 1;
        break;
      case 'q':
        quic_enabled = 1;
        break;
      case 't':
        tls_enabled = 1;
        break;
      case 'o':
        openssl_used = 1;
        break;
      case 'w':
        wolfssl_used = 1;
        break;
      default:
        usage(pname);
    }
  }
  
  tmp = openssl_used + wolfssl_used;
  if (tmp != 1)
  {
    emsg("Only one library must be specified (OPENSSL/WOLFSSL)");
    usage(pname);
  }

  tmp = dtls_enabled + quic_enabled + tls_enabled;
  if (tmp != 1)
  {
    emsg("Only one protocol must be enabled (DTLS/QUIC/TLS)");
    usage(pname);
  }

  assert(port > 0 && port < 65536);
  if (host)
  {
    imsg(APP_DEBUG_CLIENT, "Host: %s", host);
  }
  imsg(APP_DEBUG_CLIENT, "Port: %d", port);

  if (openssl_used)
  {
    imsg(APP_DEBUG_CLIENT, "The OpenSSL library is used");
    library = APP_LIBRARY_OPENSSL;
  }
  else if (wolfssl_used)
  {
    imsg(APP_DEBUG_CLIENT, "The WolfSSL library is used");
    library = APP_LIBRARY_WOLFSSL;
  }

  if (dtls_enabled)
  {
    imsg(APP_DEBUG_CLIENT, "The DTLS protocol is enabled");
    protocol = APP_PROTOCOL_DTLS;
  }
  else if (quic_enabled)
  {
    imsg(APP_DEBUG_CLIENT, "The QUIC protocol is enabled");
    protocol = APP_PROTOCOL_QUIC;
  }
  else
  {
    imsg(APP_DEBUG_CLIENT, "The TLS protocol is enabled");
    protocol = APP_PROTOCOL_TLS;
  }

	pthread_t thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

  arg = (arg_t *)malloc(sizeof(arg_t));

	ctx = init_client_ctx(library, protocol);

  arg->host = host;
  arg->port = port;
  arg->ctx = ctx;
  arg->protocol = protocol;

  rc = pthread_create(&thread, &attr, run, arg);
	if (rc) {
		emsg("return code from pthread_create: %d", rc);
		return 1;
	}

	pthread_attr_destroy(&attr);
	rc = pthread_join(thread, &status);
	if (rc) {
		emsg("return code from pthread_join: %d", rc);
		return 1;
	}

	free_client_ctx(library, protocol, ctx);

	return 0;
}

void *run(void *data)
{	
	int ret, err, server, library, protocol;
  void *session;
  arg_t *arg;
  uint8_t *p;
  uint8_t rbuf[BUF_SIZE] = {0, };
  unsigned long tstart, tmid, tend, cstart, cend;

  arg = (arg_t *)data;
  library = arg->library;
  protocol = arg->protocol;
  session = init_session(arg->ctx);
	server = init_socket(library, protocol, arg->port, 1);
  combine_session_and_socket(library, protocol, session, server);

  while (!err)
  {
    ret = run_handshake(session);
    err = process_error(session, ret);

    if (err < 0)
    {
      emsg("Error in running the handshake");
      print_error_string(library, protocol, session, ret);
      goto err;
    }
  }
  imsg(APP_DEBUG_CLIENT, "TLS session is established with %s", SSL_get_cipher(ssl));
  printf("TLS session is established with %s\n", SSL_get_cipher(ssl));

  sleep(1);
  printf("Now we send the HTTPS GET request\n");
  if (arg->content)
  {
    tstart = get_current_time();
    ret = HTTP_NOT_FINISHED;
    while (ret == HTTP_NOT_FINISHED)
      ret = send_https_message(ssl, req);
    tmid = get_current_time();


    if (ret != HTTP_SUCCESS)
    {
      emsg("Send http request error");
      goto err;
    }

    tbr = 4;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = SSL_read(ssl, rbuf+offset, tbr-offset);
      if (rcvd > 0)
        offset += rcvd;
    }
    assert(offset == tbr);

    p = rbuf;
    PTR_TO_VAR_4BYTES(p, length);

    tbr = length;
    offset = 0;
    while (offset < tbr)
    {
      if ((tbr - offset) < BUF_SIZE)
        len = (tbr - offset);
      else
        len = BUF_SIZE;
      rcvd = SSL_read(ssl, rbuf, len);
      if (rcvd > 0)
        offset += rcvd;
    }
    assert(offset == tbr);
    tend = get_current_time();
    imsg(APP_DEBUG_SERVER, "Send Time: %lu ns", tmid - tstart);
    imsg(APP_DEBUG_SERVER, "Elapsed Time: %lu ns", tend - tstart);
    imsg(APP_DEBUG_SERVER, "CPU Time: %lu ns", cend - cstart);

    printf("Received: %d bytes\n", length);
  }
    
  sleep(0.5);

err: 
	if (ssl) {
		//SSL_free(ssl);
		ssl = NULL;
	}
	if (server != -1)
  {
		close(server);
  }

	return NULL;
}

SSL_CTX* init_client_ctx(void) {
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();
	method = (SSL_METHOD *) TLS_client_method();
	ctx = SSL_CTX_new(method);

	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}

  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_verify_depth(ctx, 4);
	SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");

	return ctx;
}

void load_ecdh_params(SSL_CTX *ctx) {
	EC_KEY *ecdh;
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (!ecdh)
		perror("Couldn't load the ec key");

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
		perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

unsigned long get_current_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

unsigned long get_current_cpu(void)
{
  struct timespec tp;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp);
  return tp.tv_sec * 1000000000 + tp.tv_nsec;
}

