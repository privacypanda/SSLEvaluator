//
//  ViewController.m
//  SSLEvaluator
//
//  Created by Daniel Bates on 13/05/2021.
//

#import "ViewController.h"
#import "DetailViewController.h"

@interface ViewController()

@property (weak) IBOutlet NSTextField *hostnameTextField;
@property (weak) IBOutlet NSScrollView *progressLogTextView;
@property NSWindowController *detailWindow;
@property DetailViewController *detailVc;


@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(receivedUpdateNotification:)
                                                 name:@"LogNotification"
                                               object:nil];
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}

- (void) dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}


- (IBAction)buttonTapped:(NSButton *)sender
{
    __weak id weakSelf = self;
    [[TLSManager sharedInstance] runSSLTestsForDomain:[[self hostnameTextField]stringValue] withCompletion:^(struct EvaluationResult result) {
        
            NSString *hostname = [[self hostnameTextField]stringValue];
            NSStoryboard *storyBoard = [NSStoryboard storyboardWithName:@"Main" bundle:nil];
            NSWindowController *wc = [storyBoard instantiateControllerWithIdentifier:@"detailWindow"];
            DetailViewController *vc = [storyBoard instantiateControllerWithIdentifier:@"detailVc"];
            [vc setResult:result];
            [vc setHostname:hostname];
            [wc setContentViewController:vc];
            [wc showWindow:weakSelf];
        
    }];
    
}

- (void) appendToOutputLog: (NSString *)logMessage
{
    NSMutableAttributedString * string = [[NSMutableAttributedString alloc] initWithString:logMessage];
    [string addAttribute:NSForegroundColorAttributeName value:[NSColor greenColor] range: (NSRange){0, logMessage.length}];
    [[_progressLogTextView documentView] insertText:string];
}

- (void) receivedUpdateNotification: (NSNotification *)notification
{
    NSDictionary *userInfo = notification.userInfo;
    NSString *logMessage = [userInfo objectForKey:@"logMessage"];
    if (logMessage == nil)
    {
        return;
    }
    //Ensure UI updates are run on main queue
    dispatch_async(dispatch_get_main_queue(), ^{
        [self appendToOutputLog:logMessage];
    });
    
}



@end
