Pod::Spec.new do |s|
  s.name             = "TouchIDAuth"
  s.version          = "0.1.0"
  s.summary          = "A short description of TouchIDAuth."
  s.description      = <<-DESC
                       An optional longer description of TouchIDAuth

                       * Markdown format.
                       * Don't worry about the indent, we strip it!
                       DESC
  s.homepage         = "https://github.com/auth0/TouchIDAuth"
  # s.screenshots     = "www.example.com/screenshots_1", "www.example.com/screenshots_2"
  s.license          = 'MIT'
  s.author           = { "Hernan Zalazar" => "hernan@auth0.com" }
  s.source           = { :git => "https://github.com/auth0/TouchIDAuth.git", :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/authzero'

  s.platform     = :ios, '7.0'
  s.requires_arc = true

  s.source_files = 'Pod/Classes'
  s.resource_bundles = {
    'TouchIDAuth' => ['Pod/Assets/*.png']
  }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  s.frameworks = 'Security', 'LocalAuthentication'
  s.dependency 'SimpleKeychain', '~> 0.1'
  s.dependency 'libextobjc', '~> 0.4'
  s.dependency 'ObjectiveSugar', '~> 1.1'
end
