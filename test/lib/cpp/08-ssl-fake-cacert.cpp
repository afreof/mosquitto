#include <errno.h>
#include <mosquitto/libmosquittopp.h>
#include "path_helper.h"

class mosquittopp_test : public mosqpp::mosquittopp
{
public:
	mosquittopp_test(const char *id);

	void on_connect(int rc);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}


void mosquittopp_test::on_connect(int rc)
{
	(void)rc;
	exit(1);
}


int main(int argc, char *argv[])
{
	mosquittopp_test *mosq;
	int rc;

	if(argc != 2){
		return 1;
	}
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("08-ssl-fake-cacert");

	char cafile[4096];
	cat_sourcedir_with_relpath(cafile, "/../../ssl/test-fake-root-ca.crt");
	char capath[4096];
	cat_sourcedir_with_relpath(capath, "/../../ssl/certs");
	char certfile[4096];
	cat_sourcedir_with_relpath(certfile, "/../../ssl/client.crt");
	char keyfile[4096];
	cat_sourcedir_with_relpath(keyfile, "/../../ssl/client.key");

	mosq->tls_set(cafile, NULL, certfile, keyfile);
	rc = mosq->connect("localhost", port, 60);
	if(rc == MOSQ_ERR_SUCCESS){
		rc = mosq->loop_forever();
	}
	int err = errno;
	delete mosq;
	mosqpp::lib_cleanup();
	/* The handshake fails in connect() if the server's reply arrives before it
	 * returns, e.g. under valgrind, and in the loop otherwise. */
	if(rc == MOSQ_ERR_TLS || (rc == MOSQ_ERR_ERRNO && err == EPROTO)){
		return 0;
	}else{
		return 1;
	}
}
