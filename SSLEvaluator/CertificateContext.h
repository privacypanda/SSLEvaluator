//
//  X509Cert.h
//  SSLEvaluator
//
//  Created by Daniel Bates on 16/05/2021.
//

#import <Foundation/Foundation.h>
#import "EvaluationResult.h"
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/x509_vfy.h"

NS_ASSUME_NONNULL_BEGIN

@interface CertificateContext : NSObject

@property (nonatomic, strong) NSString *connectionHostname;
@property (nonatomic, strong) NSString *trustedCABundleLocation;

- (instancetype)initWithHostname:(NSString *)hostname trustedCACertBundle:(NSString *)bundleLocation;
- (struct EvaluationResult)runCertificateCheck;

@end

NS_ASSUME_NONNULL_END
