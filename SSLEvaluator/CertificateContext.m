//
//  X509Cert.m
//  SSLEvaluator
//
//  Created by Daniel Bates on 16/05/2021.
//

#import "CertificateContext.h"
#import "CertificateParser.hpp"

@implementation CertificateContext

- (instancetype)initWithHostname:(NSString *)hostname trustedCACertBundle:(NSString *)bundleLocation
{
    
    self = [super init];
    if (self) {
        [self setConnectionHostname:hostname];
        [self setTrustedCABundleLocation:bundleLocation];
        
    }
    return self;
}

- (struct EvaluationResult)runCertificateCheck
{
    struct EvaluationResult result;
    result.isValid = NO;
    result.errorStr = nil;
    
    NSString *log = [[NSString alloc] initWithFormat:@"Starting TLS connection to %@...\n", [self connectionHostname]];
    [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": log}];
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl;
    
    //Set the Root CA trusted certificates for the SSL connection context.
    const char *bundleLocation = [[self trustedCABundleLocation] cStringUsingEncoding:NSUTF8StringEncoding];
    if(! SSL_CTX_load_verify_locations(ctx, bundleLocation, NULL))
    {
        NSString *log = [[NSString alloc] initWithFormat:@"Failed to load trust store\n Aborted.\n"];
        [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": log}];
        NSLog(@"Failed to load trust store");
        return result;
    }
    //SSL BIO is a IO abstraction for internal handling of read/write buffers and storage objects.
    BIO* bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    //Set mode to auto retry so we automatically re-try handshake if connection drops.
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    
    //Setup connection to remote host
    NSString *connectionString = [NSString stringWithFormat:@"%@:443", [self connectionHostname]];
    
    //Set server hostname
    BIO_set_conn_hostname(bio, [connectionString cStringUsingEncoding:NSUTF8StringEncoding]);
    
    /*IMPORTANT: We need to set the SNI (Server name indicator) for the connection so that the remote host
     knows which certificate to send back.
    */
    [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": [[NSString alloc] initWithFormat:@"Setting SNI to %@\n", [self connectionHostname]]}];
    SSL_set_tlsext_host_name(ssl, [_connectionHostname cStringUsingEncoding:NSUTF8StringEncoding]);

    //Verify the connection opened and perform the TLS 3-wayhandshake

    if(BIO_do_connect(bio) <= 0)
    {
        //Connection has failed, would normally find errors etc.
        [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": [[NSString alloc] initWithFormat:@"TLS connection to host failed\nAborting\n"]}];
        return result;
    }
    
    [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": [[NSString alloc] initWithFormat:@"Connection Succeeded!\n"]}];
        
    NSLog(@"Connection successful!\n");
    
    /*Now we have an open connection to the remote host we can
     go and pull the stack of certificates (end client, up through any intermediate and finally root signing cert)
    */
    
    [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": [[NSString alloc] initWithFormat:@"Pulling client certificate...\n"]}];
    
    STACK_OF(X509) *sk = sk_X509_new_null();
    X509 *cert = SSL_get_peer_certificate(ssl);
    sk_X509_push(sk, cert);
    
    //Get chain certs
    STACK_OF(X509) *chainStack = sk_X509_new_null();
    chainStack = SSL_get_peer_cert_chain(ssl);
    
    if (NULL == cert)
    {
        [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": [[NSString alloc] initWithFormat:@"Unable to get end entity certificate\nAborting\n"]}];
        return result;
    }
    
    
    [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": [[NSString alloc] initWithFormat:@"Got client certificate!\n"]}];
    

    X509_STORE         *store = NULL;
    X509_STORE_CTX  *vrfy_ctx = NULL;
    int ret;
    
    //Initialize the certificate validation store object.
    if (!(store=X509_STORE_new()))
    {
        NSLog(@"Error creating X509_STORE_CTX object\n");
        NSString *log = [[NSString alloc] initWithFormat:@"Error creating X509_STORE_CTX object\n"];
        [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": log}];
    }
        

   
    //Create the context structure for the validation operation. *
    vrfy_ctx = X509_STORE_CTX_new();
    ret = X509_STORE_load_locations(store, [[self trustedCABundleLocation]cStringUsingEncoding:NSUTF8StringEncoding], NULL);
    if (ret != 1)
    {
        NSString *log = [[NSString alloc] initWithFormat:@"Error loading CA cert or chain file\n"];
        [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": log}];
        NSLog(@"Error loading CA cert or chain file\n");
    }
        

    /*
    * Initialize the ctx structure for a verification operation:
    * Set the trusted cert store, the client certificate, and the
    * peers chain certificate we got when connected to client
    */
    X509_STORE_CTX_init(vrfy_ctx, store, cert, chainStack);

      /* ---------------------------------------------------------- *
       * Check the complete cert chain can be build and validated.  *
       * Returns 1 on success, 0 on verification failures, and -1   *
       * for trouble with the ctx object (i.e. missing certificate) *
       * ---------------------------------------------------------- */
    ret = X509_verify_cert(vrfy_ctx);
    NSLog(@"Certificate verify return code: %d\n", ret);
    NSString *verificationLog = [[NSString alloc] initWithFormat:@"Certificate verify return code: %d\n", ret];
    [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": verificationLog}];
    
    if(ret == 0) {
        //Certificate verification has failed
        //Lets get the offending certificate and the error reason
        //for verification failure.
        char data[500];
        X509 *cert = X509_STORE_CTX_get_current_cert(vrfy_ctx);
        int depth = X509_STORE_CTX_get_error_depth(vrfy_ctx);
        int err = X509_STORE_CTX_get_error(vrfy_ctx);
                
        NSLog(@"-Error with certificate at depth: %i\n", depth);
        NSString *errCertLog = [[NSString alloc] initWithFormat:@"-Error with certificate at depth: %i\n", depth];
        [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": errCertLog}];
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        NSLog(@"  issuer   = %s\n", data);
        NSString *issuerCertLog = [[NSString alloc] initWithFormat:@"  issuer   = %s\n", data];
        [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": issuerCertLog}];
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        NSLog(@"  subject  = %s\n", data);
        NSString *subjectCertLog = [[NSString alloc] initWithFormat:@"  subject  = %s\n", data];
        [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": subjectCertLog}];
        NSLog(@"  err %i:%s\n", err, X509_verify_cert_error_string(err));
        NSString *finalCertLog = [[NSString alloc] initWithFormat:@"  err %i:%s\n", err, X509_verify_cert_error_string(err)];
        [[NSNotificationCenter defaultCenter] postNotificationName: @"LogNotification" object:self userInfo:@{@"logMessage": finalCertLog}];
        const char *error = X509_verify_cert_error_string(err);
        result.errorStr = error;
    } else {
        result.isValid = true;
    }
    
    
    //TODO:Cleanup, all openssl types will leak!!!
    
    result.certificate = cert;

    return result;
    
}


/*
 This method converts X509 OpenSSL object to a Apple friendly SecCertificateRef (not used here, just demo'd)
 */

- (SecCertificateRef)getSecCertRefFromX509: (X509 *)x509Certificate
{
    
    BIO *temp_bio = BIO_new(BIO_s_mem());
    i2d_X509_bio(temp_bio, x509Certificate);
    BIO_flush(temp_bio);
    char *x509;
    long x509Length = BIO_get_mem_data(temp_bio, &x509);
    NSData *certData = [NSData dataWithBytes:x509 length:x509Length];
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
    BIO_free_all(temp_bio);
    
    return cert;
}



@end

