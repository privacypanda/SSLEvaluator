//
//  TLSManager.m
//  SSLEvaluator
//
//  Created by Daniel Bates on 16/05/2021.
//

#import "TLSManager.h"
#import "CertificateContext.h"
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "ssl_thread.h"

@interface TLSManager()

@property (nonatomic, strong) NSString *trustedCABundle;

@end

@implementation TLSManager

/*
 Setup shared instance for TLS manager, only required once as this class manages
 entire SSL evaluation process and dispatch group management.
*/

+ (instancetype)sharedInstance
{
    static TLSManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });

    return sharedInstance;
}

/*
 The init should be still public as we dont _strictly_ require only one instance
 this would allow for a second non-shared instance to be created e.g unit testing
 purposes.
 */

- (instancetype)init
{
    if ( (self = [super init]) )
    {
        //Init OpenSSL C API, initilizer should fail here if we cannot start the SSL library.
        if (![self setupTLS]) {
            return nil;
        }
    }
    return self;
}


-(BOOL)setupTLS
{
    //First we need to init the OpenSSL library, error strings and BIO objects
    int result =  SSL_library_init();
    if (result > 0) {
        const char* versionString = SSLeay_version(SSLEAY_VERSION);
        NSLog(@"OpenSSL Version is: %@", [[NSString alloc] initWithCString:versionString encoding:NSUTF8StringEncoding]);
    } else {
        return NO;
    }
    result = THREAD_setup();
    if (result > 0) {
        NSLog(@"OpenSSL Threading init success\n");
    } else {
        return NO;
    }
    

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    
    //Attempt to load the trusted CA certs bundle used for later verification (Use mozilla trust store)
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"cacert" ofType:@"pem"];
    NSError *error;
    NSString *caBundleContents = [[NSString alloc] initWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:&error];
    
    if (caBundleContents != nil) {
        _trustedCABundle = caBundleContents;
        NSLog(@"Successfully loaded trusted CA bundle");
    } else {
        return NO;
    }
    
    return YES;
}


- (void)runSSLTestsForDomain:(NSString*)domain withCompletion:(void (^)(struct EvaluationResult result))completionBlock
{
    NSString *bundleFilePath = [[NSBundle mainBundle] pathForResource:@"cacert" ofType:@"pem"];
    CertificateContext *certContext = [[CertificateContext alloc]initWithHostname:domain trustedCACertBundle:bundleFilePath];
    
    struct EvaluationResult result = [self validateCertificateForDomain:domain managedCertContext:certContext];
    completionBlock(result);
    
}

- (struct EvaluationResult)validateCertificateForDomain:(NSString*)domain managedCertContext: (CertificateContext *)context
{
    struct EvaluationResult siteCertificateResult = [context runCertificateCheck];

    return siteCertificateResult;
}

@end
