version = `agvtool mvers -terse1`.strip
Pod::Spec.new do |s|
  s.name             = "TouchIDAuth"
  s.version          = version
  s.summary          = "A library for passwordless authentication using TouchID & JWT"
  s.description      = <<-DESC
iOS library that implements a passwordless flow using TouchID & JWT.
The authentication flow has these steps:

* TouchID validation
* Public/Private Key handling
* JWT generation & signing

It provides callbacks to implement the interaction with your backend in order to:

* Associate a public key to a user (Used to validate the signed JWT)
* Authenticate using the generated JWT.
                       DESC
  s.homepage         = "https://github.com/auth0/TouchIDAuth"
  s.license          = 'MIT'
  s.author           = { "Hernan Zalazar" => "hernan@auth0.com" }
  s.source           = { :git => "https://github.com/auth0/TouchIDAuth.git", :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/auth0'

  s.platform     = :ios, '7.0'
  s.requires_arc = true

  s.source_files = 'TouchIDAuth/*.{h,m}'

  s.frameworks = 'Security', 'LocalAuthentication'
  s.dependency 'SimpleKeychain', '~> 0.3'
end
