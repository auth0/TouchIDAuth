// A0RSAKeyExporterSpec.m
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
#import "A0RSAKeyExporter.h"


SpecBegin(A0RSAKeyExporter)

describe(@"A0RSAKeyExporter", ^{

    __block A0RSAKeyExporter *exporter;

    beforeEach(^{
        exporter = [[A0RSAKeyExporter alloc] init];
    });

    describe(@"export public key", ^{

        it(@"should return nil when data is nil", ^{
            expect([exporter exportPublicKey:nil]).to.beNil();
        });

        context(@"valid data", ^{

            __block NSString *exported;

            beforeEach(^{
                NSData *data = [[[NSUUID UUID] UUIDString] dataUsingEncoding:NSUTF8StringEncoding];
                exported = [[NSString alloc] initWithData:[exporter exportPublicKey:data] encoding:NSUTF8StringEncoding];
            });

            it(@"should contain header", ^{
                expect(exported).to.startWith(@"-----BEGIN RSA PUBLIC KEY-----");
            });

            it(@"should contain footer", ^{
                expect(exported).to.endWith(@"-----END RSA PUBLIC KEY-----");
            });

            it(@"should have 3 parts", ^{
                expect([exported componentsSeparatedByString:@"\n"]).to.haveCountOf(3);
            });

            it(@"should have key in base64 with max length of 64", ^{
                NSString *keyPart = [exported componentsSeparatedByString:@"\n"][1];
                expect(keyPart.length).to.beInTheRangeOf(1, 64);
            });
        });
    });
});

SpecEnd
