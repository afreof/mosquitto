/*
Copyright (c) 2026 Adrian Freihofer <adrian.freihofer@siemens.com>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Adrian Freihofer - initial implementation.
*/

/*
 * Certificate file watcher.
 *
 * When tls_cert_watch polling is configured the broker periodically
 * stat()s each TLS listener's certfile, keyfile, cafile and crlfile.
 * If any file's mtime has changed since the last check, the full
 * SSL_CTX for that listener is rebuilt via listeners__reload_all_certificates().
 *
 * The watch mode is selected at runtime via the tls_cert_watch config option
 * (mosquitto__cert_watch_mode enum).  Future backends (e.g. inotify) can
 * be added as additional enum values and handled in cert_watch__check().
 */

#include "config.h"

#ifdef WITH_TLS

#include <sys/stat.h>
#include <string.h>
#include <time.h>

#include "mosquitto_broker_internal.h"
#include "logging_mosq.h"

/* Per-listener snapshot of the mtimes of the TLS files we are watching.
 * We store nanosecond-precision timestamps (st_mtim) so that rapid file
 * rotations within the same wall-clock second are still detected. */
struct cert_watch_mtime {
	time_t   sec;
	long     nsec;
};

struct cert_watch_entry {
	struct cert_watch_mtime certfile_mtime;
	struct cert_watch_mtime keyfile_mtime;
	struct cert_watch_mtime cafile_mtime;
	struct cert_watch_mtime crlfile_mtime;
};

static struct cert_watch_entry *watch_entries = NULL;
static time_t next_poll_s = 0;


static struct cert_watch_mtime file_mtime(const char *path)
{
	struct cert_watch_mtime mt = {0, 0};
	struct stat st;
	if(path == NULL || stat(path, &st) != 0){
		return mt;
	}
	mt.sec  = st.st_mtim.tv_sec;
	mt.nsec = st.st_mtim.tv_nsec;
	return mt;
}

static bool mtime_changed(struct cert_watch_mtime a, struct cert_watch_mtime b)
{
	return a.sec != b.sec || a.nsec != b.nsec;
}


/* Snapshot the current mtimes of all TLS files for listener i. */
static void cert_watch__snapshot(int i)
{
	struct mosquitto__listener *listener = &db.config->listeners[i];
	watch_entries[i].certfile_mtime = file_mtime(listener->certfile);
	watch_entries[i].keyfile_mtime  = file_mtime(listener->keyfile);
	watch_entries[i].cafile_mtime   = file_mtime(listener->cafile);
	watch_entries[i].crlfile_mtime  = file_mtime(listener->crlfile);
}


/*
 * Called once at broker startup (or after config reload) to take the initial
 * mtime snapshots and schedule the first poll.
 */
void cert_watch__init(void)
{
	if(db.config->tls_cert_watch == cert_watch_disabled){
		return;
	}

	mosquitto_free(watch_entries);
	watch_entries = NULL;
	if(db.config->listener_count == 0){
		return;
	}

	watch_entries = mosquitto_calloc((size_t)db.config->listener_count,
	                                 sizeof(struct cert_watch_entry));
	if(!watch_entries){
		log__printf(NULL, MOSQ_LOG_ERR,
		            "Error: Out of memory initialising certificate watcher.");
		return;
	}

	for(int i = 0; i < db.config->listener_count; i++){
		struct mosquitto__listener *listener = &db.config->listeners[i];
		if(listener->ssl_ctx && listener->certfile && listener->keyfile){
			cert_watch__snapshot(i);
		}
	}

	next_poll_s = mosquitto_time() + (time_t)db.config->tls_cert_watch_interval;
	log__printf(NULL, MOSQ_LOG_INFO,
	            "Certificate watch: polling enabled, interval %ds.",
	            db.config->tls_cert_watch_interval);
}


/*
 * Called from the main loop before mux__handle() to ensure the multiplexer
 * wakes up no later than the next cert-watch poll deadline.  Without this,
 * the broker might sleep for sys_interval (default 10 s) between loop
 * iterations and miss a short tls_cert_watch_interval.
 */
void cert_watch__nudge_timeout(void)
{
	/* next_event_ms is not available in 2.0; this is a no-op. */
}


/*
 * Called from the main loop.  For polling mode this is a no-op until
 * tls_cert_watch_interval seconds have elapsed; then each TLS listener's
 * files are stat()d and if any mtime has changed the SSL_CTX is rebuilt.
 */
void cert_watch__check(void)
{
	if(db.config->tls_cert_watch == cert_watch_disabled){
		return;
	}
	if(watch_entries == NULL){
		return;
	}

	/* Polling mode: only act once per interval. */
	if(db.config->tls_cert_watch == cert_watch_polling){
		if(mosquitto_time() < next_poll_s){
			return;
		}
		next_poll_s = mosquitto_time() + (time_t)db.config->tls_cert_watch_interval;
	}

	for(int i = 0; i < db.config->listener_count; i++){
		struct mosquitto__listener *listener = &db.config->listeners[i];
		if(!(listener->ssl_ctx && listener->certfile && listener->keyfile)){
			continue;
		}

		struct cert_watch_mtime cert_m  = file_mtime(listener->certfile);
		struct cert_watch_mtime key_m   = file_mtime(listener->keyfile);
		struct cert_watch_mtime ca_m    = file_mtime(listener->cafile);
		struct cert_watch_mtime crl_m   = file_mtime(listener->crlfile);

		if(mtime_changed(cert_m, watch_entries[i].certfile_mtime)
				|| mtime_changed(key_m,  watch_entries[i].keyfile_mtime)
				|| mtime_changed(ca_m,   watch_entries[i].cafile_mtime)
				|| mtime_changed(crl_m,  watch_entries[i].crlfile_mtime)){

			/* Debug: report exactly which files changed. */
			if(mtime_changed(cert_m, watch_entries[i].certfile_mtime)){
				log__printf(NULL, MOSQ_LOG_DEBUG,
				            "Certificate watch: %s changed (mtime %ld.%09ld -> %ld.%09ld).",
				            listener->certfile,
				            (long)watch_entries[i].certfile_mtime.sec,
				            watch_entries[i].certfile_mtime.nsec,
				            (long)cert_m.sec, cert_m.nsec);
			}
			if(mtime_changed(key_m, watch_entries[i].keyfile_mtime)){
				log__printf(NULL, MOSQ_LOG_DEBUG,
				            "Certificate watch: %s changed (mtime %ld.%09ld -> %ld.%09ld).",
				            listener->keyfile,
				            (long)watch_entries[i].keyfile_mtime.sec,
				            watch_entries[i].keyfile_mtime.nsec,
				            (long)key_m.sec, key_m.nsec);
			}
			if(listener->cafile && mtime_changed(ca_m, watch_entries[i].cafile_mtime)){
				log__printf(NULL, MOSQ_LOG_DEBUG,
				            "Certificate watch: %s changed (mtime %ld.%09ld -> %ld.%09ld).",
				            listener->cafile,
				            (long)watch_entries[i].cafile_mtime.sec,
				            watch_entries[i].cafile_mtime.nsec,
				            (long)ca_m.sec, ca_m.nsec);
			}
			if(listener->crlfile && mtime_changed(crl_m, watch_entries[i].crlfile_mtime)){
				log__printf(NULL, MOSQ_LOG_DEBUG,
				            "Certificate watch: %s changed (mtime %ld.%09ld -> %ld.%09ld).",
				            listener->crlfile,
				            (long)watch_entries[i].crlfile_mtime.sec,
				            watch_entries[i].crlfile_mtime.nsec,
				            (long)crl_m.sec, crl_m.nsec);
			}

			log__printf(NULL, MOSQ_LOG_NOTICE,
			            "Certificate watch: change detected for listener on port %d, "
			            "triggering reload.",
			            listener->port);

			/* Stash the working SSL_CTX so that we can restore it if the new
			 * certificates fail to load (e.g. half-written file, broken chain).
			 * Setting ssl_ctx to NULL prevents net__tls_server_ctx() from
			 * freeing the old context before we know the reload succeeded. */
			SSL_CTX *old_ctx = listener->ssl_ctx;
			listener->ssl_ctx = NULL;

			if(net__tls_server_ctx(listener) != MOSQ_ERR_SUCCESS
					|| net__tls_load_verify(listener) != MOSQ_ERR_SUCCESS){

				log__printf(NULL, MOSQ_LOG_ERR,
				            "Certificate watch: failed to reload certificates for "
				            "listener on port %d — keeping existing context. "
				            "Will retry on next poll.",
				            listener->port);
				/* Discard the broken new context (may be NULL if server_ctx failed). */
				if(listener->ssl_ctx){
					SSL_CTX_free(listener->ssl_ctx);
				}
				/* Restore the working context. */
				listener->ssl_ctx = old_ctx;
				/* Do NOT update the snapshot so the next poll retries. */
				continue;
			}

			/* Reload succeeded. Release the old context. Existing SSL*
			 * connections hold their own reference so they remain valid. */
			SSL_CTX_free(old_ctx);

			/* Update the snapshot only now that the reload confirmed good. */
			watch_entries[i].certfile_mtime = cert_m;
			watch_entries[i].keyfile_mtime  = key_m;
			watch_entries[i].cafile_mtime   = ca_m;
			watch_entries[i].crlfile_mtime  = crl_m;

			log__printf(NULL, MOSQ_LOG_INFO,
			            "Certificate watch: successfully reloaded certificates for "
			            "listener on port %d.",
			            listener->port);

			/* Debug: log the SHA-1 fingerprint of the new server certificate
			 * so operators can confirm which certificate is now in use. */
			X509 *cert = SSL_CTX_get0_certificate(listener->ssl_ctx);
			if(cert){
				unsigned int fp_len = EVP_MAX_MD_SIZE;
				unsigned char fp[EVP_MAX_MD_SIZE];
				if(X509_digest(cert, EVP_sha256(), fp, &fp_len)){
					char fp_hex[EVP_MAX_MD_SIZE * 3 + 1];
					for(unsigned int j = 0; j < fp_len; j++){
						snprintf(fp_hex + j*3, 4, "%02X%s",
						         fp[j], j + 1 < fp_len ? ":" : "");
					}
					log__printf(NULL, MOSQ_LOG_DEBUG,
					            "Certificate watch: new server certificate "
					            "SHA-256 fingerprint: %s", fp_hex);
				}
			}
		}
	}
}

#endif /* WITH_TLS */
