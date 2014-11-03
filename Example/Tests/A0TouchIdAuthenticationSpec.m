// A0TouchIdAuthenticationSpec.m
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

#import "Specta.h"
#import "A0TouchIDAuthentication.h"
#import "A0TouchID.h"
#import "A0SimpleKeychain.h"

#define HC_SHORTHAND
#import <OCHamcrest/OCHamcrest.h>
#define MOCKITO_SHORTHAND
#import <OCMockito/OCMockito.h>

@interface A0TouchIDAuthentication (Testing)
@property (strong, nonatomic) A0SimpleKeychain *keychain;
@property (strong, nonatomic) A0TouchID *touchID;
@end

SpecBegin(A0TouchIdAuthentication)

describe(@"A0TouchIdAuthentication", ^{

    __block A0TouchIDAuthentication *authentication;
    __block A0TouchID *touchID;
    __block A0SimpleKeychain *keychain;

    beforeEach(^{
        authentication = [[A0TouchIDAuthentication alloc] init];
        touchID = mock(A0TouchID.class);
        keychain = mock(A0SimpleKeychain.class);
        authentication.touchID = touchID;
        authentication.keychain = keychain;
        [given(touchID.isAvailable) willReturnBool:YES];
    });

    describe(@"Starting flow", ^{

        beforeEach(^{
            authentication.registerPublicKey = ^(NSData *pubKey, A0RegisterCompletionBlock completion, A0ErrorBlock errorBlock){
            };
            authentication.authenticate = ^(NSString *jwt, A0ErrorBlock errorBlock){
            };
        });

        it(@"should fail when no callback is set", ^{
            authentication.registerPublicKey = nil;
            authentication.authenticate = nil;
            expect(^{
                [authentication start];
            }).to.raise(NSInternalInconsistencyException);
        });

        context(@"no TouchID", ^{

            __block NSError *failureReason;

            beforeEach(^{
                authentication.onError = ^(NSError *error) {
                    failureReason = error;
                };
                failureReason = nil;
                [given(touchID.isAvailable) willReturnBool:NO];
                [authentication start];
            });

            it(@"should fail", ^{
                expect(failureReason).notTo.beNil();
            });

            it(@"should have no TouchID error code", ^{
                expect(failureReason.code).to.equal(A0TouchIDAuthenticationErrorTouchIDNotAvailable);
            });

        });

        context(@"TouchID validation", ^{

            __block BOOL failed;

            beforeEach(^{
                authentication.onError = ^(NSError *error) {
                    failed = YES;
                };
                failed = NO;
            });

            it(@"should validate with TouchID", ^{
                [authentication start];
                [MKTVerify(touchID) validateWithCompletion:anything()];
            });

            it(@"should fail when TouchID validation isnt successful", ^{
                MKTArgumentCaptor *captor = [[MKTArgumentCaptor alloc] init];
                [authentication start];
                [MKTVerify(touchID) validateWithCompletion:[captor capture]];
                void (^touchBlock)(BOOL, NSError *) = captor.value;
                touchBlock(NO, nil);
                expect(failed).will.beTruthy();
            });
        });
    });
});

SpecEnd
