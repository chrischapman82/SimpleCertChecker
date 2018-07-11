/**
 *  Written by Christopher Chapman, chapmanc1, 760426, Aquarius
 *  Written for a Universtiy Project
 *  Project 2 - Computer Systems at UniMelb
 *
 *  Contains a TLS Certificate checker, checking the validity of a given certificate.
 *  Reads in a csv file specified by standard input, containing certificate file names
 *  and the domain name to compare against.
 *  Parses the certificates and validates the:
 *      Common name and alternate names match the given url_name (url_name)
 *      Key bit length
 *      Whether the certificate's times are valid against the current time
 *      Has valid extensions
 *
 *  Outputs a csv file named output.txt containing:
 *  theCertificate,domainName,ValidityOfTicket\n
 *
 *  For each line in the input file
 *  Includes base code provided in certexample by Chris Culnane
 *
 */
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>


#define CSV_LEN 2000    // MAX len for CSVs
#define DATE_LEN 128    // DATE
#define BYTE_SIZE 8     // Used for bit calculations

#define MIN_KEY_SIZE 2048   // The minimum valid key size
#define VALID_CA "CA:FALSE" // The valid string for basic constraints
// The valid string for TLS auth
#define VALID_TLS_AUTH "TLS Web Server Authentication"

// Change these to change the path to the working directory
#define FILEPATH "./"
#define OUPUT_FILE "./output.csv"

// Haha C. I will be using 1 and 0 for True and False throughout
#define TRUE 1
#define FALSE 0

// Function headers
int validate_cert(BIO *certificate_bio, X509 *cert, char* url_name);
int compare_dates(const ASN1_TIME *t1, const ASN1_TIME *t2);
int validate_key(X509 *cert);
int validate_keysize(RSA *rsa_key);
int validate_wildcard(char* wildcard, char *domain_name);
int validate_extensions(X509 *cert);
char* get_extension_data(X509 *cert, int extension_id);
int contains(char* line, char* cont);
int validate_dates(X509 *cert);
int validate_domain(X509 *cert, char* domain_name, char* possible_name);
int validate_alternate_names(X509 *cert, char* domain_name);
int validate_common_name(X509 *cert, char* domain_name);

// Debugging function headers
void print_dates(X509 *cert, ASN1_TIME *curr, ASN1_TIME *not_before, ASN1_TIME *not_after);
void print_domain_validate(X509 *cert, char* domain_name, char* cert_name);
void print_file_info(char* url, char* cert_name, char* cert_path);
int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len);
void print_key_info(RSA *rsa_key, EVP_PKEY *pkey);
void print_validate_key_size(int key_size);
void print_output(char* certificate, char* url, int is_valid);


/* The main function. Intialises openSSL, reads in csvs
 */
int main(int argc, char **argv)
{
    char csv_path[CSV_LEN];
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    char path[1000];
    
    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    
    // Check that the correct number of inputs is given
    if (argc <2) {
        fprintf(stderr, "ERROR, please provide the file path\n");
        exit(1);
    }
    
    // Parse input filename
    strcpy(csv_path, argv[1]);
    printf("Path = %s\n", csv_path);
    
    // Init INPUT_FILE to read data from
    FILE *file;
    file = fopen(csv_path, "r");
    
    // Init OUTPUT_FILE to read data to
    FILE *foutput;
    foutput = fopen(OUPUT_FILE, "w");
    if (foutput == NULL) return -1;
    
    // Reading in CSVs
    char certificate[2048];
    char url[2048];
    char line[4098];
    int i, j, is_valid;
    
    // Reading in the CSV!
    while (fgets(line, 4098, file)) {
        i=0;
        j=0;
        char* tok;
        
        // Reading in the URL
        for (tok = strtok(line, ","); tok && *tok; j++, tok = strtok(NULL, "\t\n")) {
            strcpy(url,tok);
        }
        
        // Reading in the certificate
        for (tok = strtok(line, ","); tok && *tok; j++, tok = strtok(NULL, "\t\n")) {
            strcpy(certificate,tok);
        }
        
        // Creating path name
        strcpy(path, FILEPATH);
        strcat(path, certificate);
        
        // Read certificate into BIO and checks for failures:
        certificate_bio = BIO_new(BIO_s_file());
        
        if (!(BIO_read_filename(certificate_bio, path))) {
            fprintf(stderr, "Error in reading cert BIO filename");
            exit(EXIT_FAILURE);
        }
        
        if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
            fprintf(stderr, "Error in loading certificate");
            exit(EXIT_FAILURE);
        }
        
        //print_file_info(url, certificate, path);
        
        is_valid = validate_cert(certificate_bio, cert, url);
        
        
        //print_out(certificate, url, is_valid);
        // Output to file in the given form:
        fprintf(foutput, "%s,%s,%d\n", certificate, url, is_valid);
    }
    
    // close the files
    fclose(file);
    fclose(foutput);
    
    exit(0);
}

// Debugger fn. Prints out the output that will be put into the output file
void print_output(char* certificate, char* url, int is_valid) {
    printf("Outputs: %s,%s,%d\n", certificate, url, is_valid);
}

// Debugger fn, prints out information to do with setting up the files and certificates
void print_file_info(char* url, char* cert_name, char* cert_path) {
    printf("\n*** PRINTING FILE INFO ***\n");
    printf("Reading in url: %s\n", url);
    printf("Reading in cert: %s\n", cert_name);
    printf("cert path = %s\n\n", cert_path);
}

/*  Validates a given certificate (cert)
 *  Validates following, returning 0 if any are invalid:
 *      Common name and alternate names match the given url_name (url_name)
 *      Key bit length
 *      Falls within the correct time period
 *      Has valid extensions
 *
 *  Returns 1 if all are valid
 *  Extensions found at:
 *  https://www.openssl.org/docs/man1.1.0/crypto/X509_REVOKED_get0_extensions.html
 */
int validate_cert(BIO *certificate_bio, X509 *cert, char* url_name) {
    int is_valid = 1;
    char *buf = NULL;
    BIO *b;
    
    b = BIO_new_fp(stdout, BIO_NOCLOSE);
    
    // Validating that the date is correct
    if (!validate_dates(cert)) {
        is_valid = 0;
    }
    
    // Looks at the common names to see if they match up!
    if (!validate_common_name(cert, url_name)) {
        
        // If the CN doesn't match, checks the alternate names
        if (!validate_alternate_names(cert, url_name)) {
            is_valid = 0;
        }
    }
    
    // Checks that the key is valid
    if (!validate_key(cert)) {
        is_valid = 0;
    }
    
    // Checks that the extensions are valid
    if (!validate_extensions(cert)) {
        is_valid = 0;
    }
    
    // Doesn't return early so that resources can be freed.
    X509_free(cert);
    BIO_free_all(certificate_bio);
    free(buf);
    
    return is_valid;
}

/*  Validates that the given certificate's (cert) extensions are valid
 *  Validates the following, returning 0 if any are invalid:
 *      Basic constraints has a valid CA
 *      Enhanced Key Usage contains "TLS Web Server Authentication"
 */
// for validating extensions
int validate_extensions(X509 *cert) {
    char* buff;
    
    // Checks that basic constrains has a valid CA:
    buff = get_extension_data(cert, NID_basic_constraints);
    if (strcmp(buff, VALID_CA)) {
        return 0;
    }
    
    // Checks that Enhanced Key Usage contains "TLS Web Server Authentication"
    buff = get_extension_data(cert, NID_ext_key_usage);
    if (!contains(buff, VALID_TLS_AUTH)) {
        return 0;
    }
    return 1;
}


//  Split based on: http://www.tutorialspoint.com/ansi_c/c_strtok.htm
/*  Validates that the certificate (cert) has any valid subject alternate names
 *  based on the given (domain name)
 *  Returns 1 if a valid alt name exists. Otherwise: 0
 */
int validate_alternate_names(X509 *cert, char* domain_name) {
    char* buff;
    buff = get_extension_data(cert, NID_subject_alt_name);
    
    // Returns early if there are no subject alternate names given
    if (buff == NULL) {
        return 0;
    }
    
    // Splitting the subject alternate names into tokens
    // Assumes that each alternate name will be precursered by ", DNS"
    char *curr_alt_name;
    curr_alt_name = strtok (buff,", DNS:");
    while (curr_alt_name != NULL) {
        curr_alt_name = strtok(NULL, ", DNS:");
        
        // Returns 1 if there is a valid domain
        if (validate_domain(cert, domain_name, curr_alt_name)) {
            return 1;
        }
    }
    return 0;
}
/*  Returns the string data from an extension denoted by extension_id, from a given
 *  certificate (cert)
 *  If data does not exist, returns NULL
 *  Code modified from University of Melbourne certexample.c
 *
 *  Extension-ids listed at:
 *  https://www.openssl.org/docs/man1.1.0/crypto/X509_REVOKED_get0_extensions.html
 */
char* get_extension_data(X509 *cert, int extension_id) {
    X509_NAME *cert_issuer = NULL;
    cert_issuer = X509_get_issuer_name(cert);
    char issuer_cn[256] = "Issuer CN NOT FOUND";
    X509_NAME_get_text_by_NID(cert_issuer, NID_commonName, issuer_cn, 256);
    X509_EXTENSION *ex = NULL;
    
    // Reads in the given extension, returning NULL if does not exist
    if (X509_get_ext_by_NID(cert, extension_id, -1) == -1) {
        return NULL;
    }
    
    // Gets the extension from the id
    ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, extension_id, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0)) {
        fprintf(stderr, "Error in reading extensions");
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);
    
    // Modifies the buffer to the size of the data
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';
    
    // Returns the data stored in extension
    return buf;
}

/*  Helper fn: Checks if the given text (line) contains the text (cont)
 *  Returns 1 if yes, 0 if not.
 *
 *  Basically strstr in a format that is closer to other languages
 */
int contains(char* line, char* cont) {
    
    if (strstr(line, cont) != NULL) {
        return 1;
    }
    return 0;
}


/*  Validates a key for a given certificate (cert), checking that it has a valid keysize
 *  Assumes that the key is RSA.
 */
int validate_key(X509 *cert) {
    RSA *rsa_key;
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    rsa_key = pkey->pkey.rsa;
    
    if (!validate_keysize(rsa_key)) {
        return 0;
    }
    
    //print_key_info(rsa_key, pkey);
    EVP_PKEY_free(pkey);
    
    return 1;
}

/*  Validates that a given key size (2048) has a bit size of over a minimum threshold
 */
int validate_keysize(RSA *rsa_key) {
    int key_size = 0;
    key_size = RSA_size(rsa_key);
    key_size = key_size * BYTE_SIZE;
    
    if (key_size < MIN_KEY_SIZE) {
        return 0;
    }
    // otherwise, we all good mofo
    return 1;
}

/*  Validates that the common name of the given certificate (cert) is valid against
 *  the given domain name (domain_name)
 *  Is valid if:
 *      CN from cert's domain name is the same as the domain name
 *
 *  Returns 1 if valid, else: 0
 */
int validate_common_name(X509 *cert, char* domain_name) {
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char CN[2048];
    char* tok;
    char *temp = malloc(1000);
    strcpy(temp, subj);
    
    // Iterates over tokens between each /, searching for a token beginning with CN
    tok = strtok(temp, "/");
    while(tok != NULL) {
        if (tok[0] == 'C' && tok[1] == 'N') {
            //printf("%d\n", 3);
            tok = strtok(tok, "=");
            tok = strtok(NULL, "=");
            break;
        }
        tok = strtok(NULL, "/");
    }
    strcpy(CN, tok);
    
    // Now armed with the common name CN, checks if it is valid
    return validate_domain(cert, domain_name, CN);
}

/*  Validates a candidate name (possible_name) against the domain name
 *  Is valid if:
 *      If a Wildcard (Beginning with *), checks whether the domain following the wildcard
 *          appears within the domain
 *      Otherwise, checks exact equality between the domain names
 *
 *  Returns 1 if valid, else 0
 */
int validate_domain(X509 *cert, char* domain_name, char* possible_name) {
    char* tmp_possible = malloc(1000);
    char* tmp_domain = malloc(1000); // to avoid ruining the prev strings
    
    strcpy(tmp_possible, possible_name);
    strcpy(tmp_domain, domain_name);
    
    // Test whether the current is a wildcard
    if (tmp_possible[0] == '*') {
        return validate_wildcard(tmp_possible, tmp_domain);
    }
    //print_domain_validate(cert, tmp_domain, tmp_possible);
    
    // Checks exact equality between the two strings
    if (strcmp(tmp_possible, tmp_domain) != 0) {
        return 0;
    }
    return 1;
}


/*  Validates a wildcard domain (wildcardd) against a given domain (domain_name)
 *  If the domain_name contains a wildcard, returns 1
 *  Otherwise, returns 0
 */
int validate_wildcard(char *wildcard, char *domain_name) {
    char *tok = strtok(wildcard, "*");
    char *tmp_dom = malloc(1000);
    strcpy(tmp_dom, domain_name);
    
    return contains(tmp_dom, tok);
}


/*  Validates the date of a certificate
 *  Is valid if:
 *      The current time is after the not_before time
 *      The current time is before the not_after time
 *
 *  Returns 1 if valid, otherwise 0
 */
int validate_dates(X509 *cert) {
    BIO *b;
    b = BIO_new_fp(stdout, BIO_NOCLOSE);
    
    // Getting before and after times from the certificate
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    
    // Getting the current time
    time_t t;
    t = time(NULL);
    ASN1_TIME *curr = ASN1_TIME_adj(NULL, t, 0, 0);
    
    //print_dates(cert, curr, not_before, not_after);
    BIO_free(b);
    
    // Checks that the time is all good for the not_after and not_before times
    if (compare_dates(not_before, curr) > 0 && compare_dates(curr, not_after) > 0) {
        return 1;
    }
    return 0;
}


/***************** DEBUGGING FUNCTIONS *****************/

// Helper, prints out the key size provided
void print_validate_key_size(int key_size) {
    printf("\n*** PRINTING RSA_KEY KEY SIZE *** \n");
    printf("Key size in bits %d\n", key_size);
    printf("Minimum key size = %d\n\n", MIN_KEY_SIZE);
}

void print_key_info(RSA *rsa_key, EVP_PKEY *pkey) {
    printf("\n*** PRINT RSA_KEY** \n");
    rsa_key = pkey->pkey.rsa;
    
    BIO *b;
    b = BIO_new_fp(stdout, BIO_NOCLOSE);
    printf("Size = %d\n", RSA_size(rsa_key)); // gets the size in bytes
    
    RSA_print(b, rsa_key, 0);
    BIO_free(b);
}

// Prints info to do with validating the domain
void print_domain_validate(X509 *cert, char* domain_name, char* cert_name) {
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    
    printf("\n*** PRINTING DOMAIN ***\n");
    printf("%s\n", subj);
    printf("cert_name = %s\n", cert_name);
    printf("domain name = %s\n\n", domain_name);
}

/*  Compares two times t1 and t2 that use the certificate time format
 *  if t1 > t2  -> Returns 1
 *  if t1 <= t2 -> Returns 0
 *  Only works on the nectar instance unfortunately...
 */
int compare_dates(const ASN1_TIME *t1, const ASN1_TIME *t2) {
    int days, secs;
    ASN1_TIME_diff(&days, &secs, t1, t2);
    if (days < 0) {
        return -1;
    } else if (days == 0) {
        // Same day and time is so rare that treated as invalid
        if (secs < 0) {
            return -1;
        } else {
            return 1;
        }
    } else {
        return 1;
    }
    // return 1;    // For my silly computer
}

// For printing date information
void print_dates(X509 *cert, ASN1_TIME *curr, ASN1_TIME *not_before, ASN1_TIME *not_after) {
    printf("\n*** PRINTING DATES ***\n");
    BIO *b;
    
    b = BIO_new_fp(stdout, BIO_NOCLOSE);
    
    printf("current time = ");
    ASN1_TIME_print(b, curr);
    
    // Checking out before nad after times
    printf("\nnot_before = ");
    ASN1_TIME_print(b, not_before);
    
    printf("\nnot_after = ");
    ASN1_TIME_print(b, not_after);
    printf("\n");
    
    ASN1_TIME_print(b, not_after);
    //printf("%d\n", ASN1_TIME_diff(&day, &sec, not_before, not_after));
    //ASN1_TIME_compare(not_before,not_after);
    
    printf("\ncompare_dates(not_before, curr) > 0: %d\n", compare_dates(not_before, curr) > 0);
    printf("compare_dates(curr, not_after) > 0): %d\n", compare_dates(curr, not_after) > 0);
    
    printf("\n");
    BIO_free(b);
}
