require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-certificate"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "11.0" }
  s.source       = { :git => "https://github.com/wertlop/react-native-certificate.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift}"

  s.subspec 'Static' do |sp|
      sp.source_files        = 'ios/SwiftRSACrypto/include-ios/openssl/**/*.h'
      sp.public_header_files = 'ios/SwiftRSACrypto/include-ios/openssl/**/*.h'
      sp.header_dir          = 'openssl'
      sp.xcconfig            = { "HEADER_SEARCH_PATHS" => "${PODS_ROOT}/Headers/Public/react-native-certificate/SwiftRSACrypto/include-ios" }
      sp.vendored_libraries  = 'ios/SwiftRSACrypto/include-ios/libcrypto.a', 'ios/SwiftRSACrypto/include-ios//libssl.a'
    end

  s.dependency "React-Core"
  s.dependency "SwiftyRSA"
  s.dependency "CryptoSwift"
  s.dependency "SwiftDate"
  s.dependency "ASN1Decoder"
  s.dependency "SwiftyJSON"
end
