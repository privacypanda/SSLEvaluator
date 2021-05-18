//
//  DetailViewController.m
//  SSLEvaluator
//
//  Created by Daniel Bates on 17/05/2021.
//

#import "DetailViewController.h"
#import "CertificateParser.hpp"

@interface DetailViewController ()

@property (weak) IBOutlet NSTextField *reportForTitle;
@property (weak) IBOutlet NSTextField *commonNameTextField;
@property (weak) IBOutlet NSTextField *SANTextField;
@property (weak) IBOutlet NSTextField *issuerTextField;
@property (weak) IBOutlet NSTextField *thumbprintTextField;
@property (weak) IBOutlet NSTextField *serialTextField;
@property (weak) IBOutlet NSTextField *ValidFromTextField;
@property (weak) IBOutlet NSTextField *validToTextField;
@property (weak) IBOutlet NSTextField *crlTextField;
@property (weak) IBOutlet NSTextField *ocspTextField;
@property (weak) IBOutlet NSTextField *certStatusTextField;
@property (weak) IBOutlet NSTextField *certErrorTextField;

@end

@implementation DetailViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    if (_result.certificate == nil) {
        NSLog(@"Certificate Error\n");
        return;
    }
    [[self view]setWantsLayer:YES];
    [[[self view]layer]setMasksToBounds:NO];
    CertificateParser *parser = [[CertificateParser alloc]initWithCertificate:_result.certificate];
    [self setTitle:@"Evaluation Results"];
    [[self reportForTitle] setStringValue: [NSString stringWithFormat:@"Report for %@", [self hostname]]];
    [[self commonNameTextField] setStringValue: [NSString stringWithFormat:@"Subject: %@", [parser getCommonName]]];
    
    NSArray *san = [parser getSubjectAltNames];
    NSMutableString *sanStr = [[NSMutableString alloc]init];
    if ([san count] > 10) {
        NSArray * cutDownArray = [san subarrayWithRange:NSMakeRange(0, 10)];
        [sanStr appendString:[cutDownArray componentsJoinedByString:@",\n"]];
        [sanStr appendFormat:@"\nPlus %lu more...", san.count - 10];
    }
    
    [[self SANTextField]setStringValue:[NSString stringWithFormat:@"Subject Alt Names: %@", sanStr]];
    [[self issuerTextField]setStringValue:[NSString stringWithFormat:@"Issuer: %@", [parser getIssuer]]];
    [[self thumbprintTextField]setStringValue:[NSString stringWithFormat:@"Thumbprint: %@", [parser getThumbprint]]];
    [[self serialTextField]setStringValue:[NSString stringWithFormat:@"Serial Number: %@", [parser getSerial]]];
    [[self ValidFromTextField]setStringValue:[NSString stringWithFormat:@"Valid From: %@", [parser getValidFrom]]];
    [[self validToTextField]setStringValue:[NSString stringWithFormat:@"Valid To: %@", [parser getValidTo]]];
    [[self crlTextField]setStringValue:[NSString stringWithFormat:@"CRL Endpoint: %@", [parser getCrlUrls]]];
    [[self ocspTextField]setStringValue:[NSString stringWithFormat:@"OCSP Endpoint: %@", [parser getOcspURLs]]];
    
    if (_result.errorStr == nil && _result.isValid == YES)
    {
        [[self certStatusTextField]setStringValue:[NSString stringWithFormat:@"Status: Trusted!"]];
        [[self certErrorTextField]setStringValue:[NSString stringWithFormat:@"Error: None"]];
    } else {
        [[self certStatusTextField]setStringValue:[NSString stringWithFormat:@"Status: Untrusted!"]];
        [[self certErrorTextField]setStringValue:[NSString stringWithFormat:@"Error: %@", [NSString stringWithCString:_result.errorStr encoding:NSUTF8StringEncoding]]];
    }
    
}

-(void)viewDidAppear
{
    return;
}

- (void)dealloc
{
    //X509_free(_result.certificate);
}

@end
