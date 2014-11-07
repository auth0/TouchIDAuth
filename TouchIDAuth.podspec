Pod::Spec.new do |s|
  s.name             = "TouchIDAuth"
  s.version          = "0.1.0"
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

  s.source_files = 'Pod/Classes'

  # s.public_header_files = 'Pod/Classes/**/*.h'
  s.frameworks = 'Security', 'LocalAuthentication'
  s.dependency 'SimpleKeychain', '~> 0.2'
  s.dependency 'libextobjc', '~> 0.4'
  s.dependency 'ObjectiveSugar', '~> 1.1'
end
