// A0ViewController.m
//
// Copyright (c) 2014 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "A0ViewController.h"

#import <TouchIDAuth/A0TouchIDAuthentication.h>
#import <AFNetworking/AFNetworking.h>

#define kBaseURL @"http://localhost:3000"

@interface A0ViewController ()
@property (strong, nonatomic) A0TouchIDAuthentication *authentication;
@end

@implementation A0ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.authentication = [[A0TouchIDAuthentication alloc] init];
    [self.authentication reset];
    NSURL *baseURL = [NSURL URLWithString:kBaseURL];
    AFHTTPRequestOperationManager *manager = [[AFHTTPRequestOperationManager alloc] initWithBaseURL:baseURL];
    manager.requestSerializer = [AFJSONRequestSerializer serializer];
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [self.authentication reset];
    self.authentication.registerPublicKey = ^(NSData *pubKey, A0RegisterCompletionBlock completionBlock, A0ErrorBlock errorBlock) {
        NSDictionary *params = @{
                                 @"user": @"mail@mail.com",
                                 @"key": [pubKey base64EncodedStringWithOptions:0],
                                 };
        [manager POST:@"/pubkey" parameters:params success:^(AFHTTPRequestOperation *operation, id responseObject) {
            completionBlock();
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            errorBlock(error);
        }];
    };

    self.authentication.authenticate = ^(NSString *jwt, A0ErrorBlock errorBlock) {
        NSLog(@"JWT: %@", jwt);
        NSDictionary *params = @{
                                 @"jwt": jwt,
                                 };
        [manager POST:@"/login" parameters:params success:^(AFHTTPRequestOperation *operation, id responseObject) {
            NSLog(@"Logged in!!!");
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            errorBlock(error);
        }];
    };
    self.authentication.onError = ^(NSError *error) {
        NSLog(@"ERROR %@", error);
    };
    [self.authentication start];
}

@end
