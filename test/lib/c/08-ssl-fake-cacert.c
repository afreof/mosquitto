#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>

#include "path_helper.h"


static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;
	(void)rc;

	exit(1);
}


int main(int argc, char *argv[])
{
	int rc;
	int err;
	struct mosquitto *mosq;
	int port;

	if(argc < 2){
		return 1;
	}
	port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("08-ssl-connect-crt-auth", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	char cafile[4096];
	cat_sourcedir_with_relpath(cafile, "/../../ssl/test-fake-root-ca.crt");
	char certfile[4096];
	cat_sourcedir_with_relpath(certfile, "/../../ssl/client.crt");
	char keyfile[4096];
	cat_sourcedir_with_relpath(keyfile, "/../../ssl/client.key");
	mosquitto_tls_set(mosq, cafile, NULL, certfile, keyfile, NULL);
	mosquitto_connect_callback_set(mosq, on_connect);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc == MOSQ_ERR_SUCCESS){
		rc = mosquitto_loop_forever(mosq, -1, 1);
	}
	err = errno;
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	/* The handshake fails in mosquitto_connect() if the server's reply arrives
	 * before it returns, e.g. under valgrind, and in the loop otherwise. */
	if(rc == MOSQ_ERR_TLS || (rc == MOSQ_ERR_ERRNO && err == EPROTO)){
		return 0;
	}else{
		return 1;
	}
}

