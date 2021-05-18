//
//  EvaluationResult.m
//  SSLEvaluator
//
//  Created by Daniel Bates on 17/05/2021.
//

#import <Foundation/Foundation.h>
#import "openssl/x509.h"

struct EvaluationResult {
    X509 *certificate;
    BOOL isValid;
    char *errorStr;
};
