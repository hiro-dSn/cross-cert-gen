/* ======================================================================
     cross-cert-gen - Cross-Certificate Generator
     [ cross-cert-gen_main.c ]
     Written by Hiroshi KIHIRA, based on openssl/apps.
   ====================================================================== */

/* --- Header files --- */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>


#define FAKE_CERT_V3EXT "fake_extensions"
BIO *bio_stdout = NULL;


/* ----------------------------------------------------------------------
     _read_pem_cert: Load x509 certificate and print detail
   ---------------------------------------------------------------------- */
X509* _read_pem_cert(char *filename, char *desc)
{
	X509 *cert = NULL;
	FILE *cert_fp = NULL;
	ASN1_INTEGER *serial = NULL;
	X509_NAME *subject = NULL;
	ASN1_TIME *startdate = NULL;
	ASN1_TIME *enddate = NULL;

	fprintf(stdout, "Loading %s ... ", desc);
	if ((cert_fp = fopen(filename, "r")) == NULL) {
		fprintf(stdout, "Failed\n");
		fprintf(stderr, "[ERROR] Can not open: %s.\n", filename);
		return NULL;
	}
	if ((cert = PEM_read_X509(cert_fp, NULL,
		                          (pem_password_cb *)NULL,
		                          desc)) == NULL) {
		fprintf(stdout, "Failed\n");
		fprintf(stderr, "[ERROR] PEM_read_X509_AUX() Failed: %s\n", filename);
		fclose(cert_fp);
		return NULL;
	}
	fclose(cert_fp);
	fprintf(stdout, "\n");

	serial = X509_get_serialNumber(cert);
	subject = X509_get_subject_name(cert);
	startdate = X509_get_notBefore(cert);
	enddate = X509_get_notAfter(cert);

	BIO_printf(bio_stdout, "  Serial: ");
	BN_print(bio_stdout, ASN1_INTEGER_to_BN(serial, NULL));
	BIO_printf(bio_stdout, "\n");

	BIO_printf(bio_stdout, "  Subject: ");
	X509_NAME_print(bio_stdout, subject, 16);
	BIO_printf(bio_stdout, "\n");

	BIO_printf(bio_stdout, "  notBefore: ");
	ASN1_TIME_print(bio_stdout, startdate);
	BIO_printf(bio_stdout, "\n");
	BIO_printf(bio_stdout, "  notAfter: ");
	ASN1_TIME_print(bio_stdout, enddate);
	BIO_printf(bio_stdout, "\n");

	return cert;
}


/* ----------------------------------------------------------------------
     _read_pem_privkey: Load PEM privatekey and print detail
   ---------------------------------------------------------------------- */
EVP_PKEY* _read_pem_privkey(char *filename, char *desc)
{
	EVP_PKEY *privkey = NULL;
	FILE *privkey_fp = NULL;

	fprintf(stdout, "Loading %s ... ", desc);
	if ((privkey_fp = fopen(filename, "r")) == NULL) {
		fprintf(stdout, "Failed\n");
		fprintf(stderr, "[ERROR] Can not open: %s.\n", filename);
		return NULL;
	}
	if ((privkey = PEM_read_PrivateKey(privkey_fp, NULL,
		                               (pem_password_cb *)NULL,
		                               desc)) == NULL) {
		fprintf(stdout, "Failed\n");
		fprintf(stderr, "[ERROR] PEM_read_PrivateKey() Failed: %s\n",
		        filename);
		fclose(privkey_fp);
		return NULL;
	}
	fclose(privkey_fp);
	fprintf(stdout, "\n");

	EVP_PKEY_print_public(bio_stdout, privkey, 2, NULL);

	return privkey;
}


/* ----------------------------------------------------------------------
     _write_pem_cert: Write x509 certificate and print detail
   ---------------------------------------------------------------------- */
int _write_pem_cert(X509 *cert, char *filename, char *desc)
{
	FILE *cert_fp = NULL;
	struct stat stat_buf;

	if (stat(filename, &stat_buf) == 0) {
		fprintf(stderr, "[ERROR] Output file exists: %s.\n", filename);
		return -1;
	}
	fprintf(stdout, "\nWriting %s ... ", desc);
	if ((cert_fp = fopen(filename, "w")) == NULL) {
		fprintf(stdout, "Failed\n");
		fprintf(stderr, "[ERROR] Can not open: %s.\n", filename);
		return -1;
	}
	if (!PEM_write_X509(cert_fp, cert)) {
		fprintf(stdout, "Failed\n");
		fprintf(stderr, "[ERROR] PEM_write_X509_AUX() Failed\n");
		fclose(cert_fp);
		return -1;
	}
	fclose(cert_fp);

	fprintf(stdout, "\n\n");
	X509_print(bio_stdout, cert);

	return 0;
}


/* ----------------------------------------------------------------------
     MAIN:
   ---------------------------------------------------------------------- */
int main (int argc, char *argv[])
{
	X509 *ca_cert = NULL;
	X509 *tgt_cert = NULL;
	X509 *out_cert = NULL;
	EVP_PKEY *ca_pkey = NULL;
	const EVP_MD *md = NULL;
	CONF *req_conf = NULL;
	long errorline = -1;
	X509V3_CTX v3_ctx;

	OpenSSL_add_all_algorithms();
	bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

	if (argc != 6) {
		fprintf(stderr, "[ERROR] Invalid argument.\n");
		exit(1);
	}

	/* Load input files */
	if ((tgt_cert = _read_pem_cert(argv[1], "Target Certificate")) == NULL) {
		exit(2);
	}
	if ((ca_cert = _read_pem_cert(argv[2], "CA Certificate")) == NULL) {
		exit(2);
	}
	if ((ca_pkey = _read_pem_privkey(argv[3], "CA Private Key")) == NULL) {
		exit(2);
	}

	/* Check loaded ca_cert, ca_pkey */
	if (!X509_check_private_key(ca_cert, ca_pkey)) {
		fprintf(stderr, "[ERROR] CA Cert/CA Key mismatch.\n");
	}

	/* Load openssl.cnf */
	fprintf(stdout, "\nLoading configuration file ... \n");
	req_conf = NCONF_new(NULL);
	if (!NCONF_load(req_conf, argv[4], &errorline)) {
		fprintf(stderr, "[ERROR] NCONF_load() Failed.\n");
		exit(2);
	}
	if (CONF_modules_load(req_conf, NULL, 0) <= 0) {
		fprintf(stderr, "[ERROR] CONF_modules_load() Failed.\n");
		exit(2);
	}

	/* Gen cross-cert */
	fprintf(stdout, "\nGenerating Cross-Certificate ... \n");

	out_cert = X509_new();
	X509_set_version(out_cert, 2L);
	X509_set_serialNumber(out_cert, X509_get_serialNumber(tgt_cert));
	X509_set_subject_name(out_cert, X509_get_subject_name(tgt_cert));
	X509_set_issuer_name(out_cert, X509_get_subject_name(ca_cert));
	X509_set_notBefore(out_cert, X509_get_notBefore(tgt_cert));
	X509_set_notAfter(out_cert, X509_get_notAfter(tgt_cert));
	X509_set_pubkey(out_cert, X509_get_pubkey(tgt_cert));

	X509V3_set_ctx(&v3_ctx, ca_cert, out_cert, NULL, NULL, 0);
	X509V3_set_nconf(&v3_ctx, req_conf);
	if (!X509V3_EXT_add_nconf(req_conf, &v3_ctx, FAKE_CERT_V3EXT, out_cert)) {
		fprintf(stderr, "X509V3_EXT_add_nconf() Failed\n");
		exit(2);
	}

	/* Sign target cross-certificate */
	md = EVP_sha256();
	X509_sign(out_cert, ca_pkey, md);

	/* Save generated cross-certificate */
	if (_write_pem_cert(out_cert, argv[5], "Generated Certificate") != 0) {
		exit(2);
	}

	NCONF_free(req_conf);
	X509_free(ca_cert);
	X509_free(tgt_cert);
	X509_free(out_cert);
	EVP_PKEY_free(ca_pkey);
	EVP_cleanup();

	return 0;
}
