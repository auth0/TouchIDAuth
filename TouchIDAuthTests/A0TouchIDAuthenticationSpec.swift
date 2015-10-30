// A0TouchIDAuthenticationSpec.swift
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

import Quick
import Nimble
import JWTDecode

class MockTouchID: A0TouchID {
    var availavility: Bool = true
    var onValidation: () -> (valid: Bool, error: NSError?) = { return (true, nil) }

    override var available: Bool {
        return self.availavility
    }

    override func validateWithCompletion(completionBlock: ((Bool, NSError!) -> Void)!, localizedReason reason: String!) {
        let result = onValidation()
        completionBlock(result.valid, result.error)
    }
}

class A0TouchIDAuthenticationSpec: QuickSpec {

    override func spec() {
        var authentication: A0TouchIDAuthentication!
        var touchID: MockTouchID!

        beforeEach {
            touchID = MockTouchID()
            authentication = A0TouchIDAuthentication()
            authentication.touchID = touchID
            authentication.registerPublicKey = { (_, completion, _) in completion() }
            authentication.authenticate = { (jwt, error) in }
        }

        afterEach {
            authentication.reset()
        }

        describe("authentication") {

            it("should register public key") {
                authentication.reset()
                waitUntil { done in
                    authentication.registerPublicKey = { (_, _, _) in
                        done()
                    }
                    authentication.start()
                }
            }

            it("should only register public key once") {
                authentication.start()
                authentication.registerPublicKey = { (_, _, _) in fail("public key already registered") }
                authentication.start()
            }

            it("should not start without callbacks") {
                authentication = A0TouchIDAuthentication()
                authentication.touchID = touchID
                expect {
                    authentication.start()
                }.to(raiseException())
            }

            it("should fail with when TouchID is not available") {
                touchID.availavility = false
                waitUntil { done in
                    authentication.onError = { error in
                        expect(error.code).to(equal(A0TouchIDAuthenticationError.TouchIDNotAvailable.rawValue))
                        done()
                    }
                    authentication.start()
                }
            }

            it("should call error callback on TouchID validation failure") {
                touchID.onValidation = { return (false, nil) }
                waitUntil { done in
                    authentication.onError = { error in
                        expect(error.code).to(equal(A0TouchIDAuthenticationError.TouchIDFailed.rawValue))
                        done()
                    }
                    authentication.start()
                }
            }

            describe("jwt payload") {
                it("should include default values") {
                    waitUntil { done in
                        authentication.authenticate = { (jwtString, _) in
                            let jwt = try! decode(jwtString)
                            expect(jwt.expiresAt).notTo(beNil())
                            expect(jwt.issuedAt).notTo(beNil())
                            expect(jwt.subject).notTo(beNil())
                            expect(jwt.claim("device") as String?).to(equal(UIDevice.currentDevice().name))
                            done()
                        }
                        authentication.start()
                    }
                }

                it("should expire 30 seconds after issued") {
                    waitUntil { done in
                        authentication.authenticate = { (jwtString, _) in
                            let jwt = try! decode(jwtString)
                            let expiresIn = jwt.expiresAt!.timeIntervalSinceDate(jwt.issuedAt!)
                            expect(expiresIn).to(equal(30))
                            done()
                        }
                        authentication.start()
                    }
                }

                it("should also include custom values") {
                    waitUntil { done in
                        authentication.jwtPayload = { return ["custom": "custom_value"] }
                        authentication.authenticate = { (jwtString, _) in
                            let jwt = try! decode(jwtString)
                            expect(jwt.expiresAt).notTo(beNil())
                            expect(jwt.issuedAt).notTo(beNil())
                            expect(jwt.subject).notTo(beNil())
                            expect(jwt.claim("custom") as String?).notTo(beNil())
                            done()
                        }
                        authentication.start()
                    }
                }

            }
        }
    }
}
