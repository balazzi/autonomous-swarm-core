# Native static assembly integration contract for Xcode toolchains.
Pod::Spec.new do |s|
  s.name             = 'SwarmCoreCore'
  s.version          = '2.0.0'
  s.summary          = 'Bare-metal post-quantum resilient 15-agent swarm framework.'
  s.description      = 'Zero-dependency machine-code layer: topological analytics, lattice crypto, thermodynamic governor.'
  s.homepage         = 'https://swarm-security.internal'
  s.license          = { :type => 'Commercial', :text => 'Copyright 2026 Core Architecture Team.' }
  s.author           = { 'Lead Architect Engineer' => 'core-engine@quantum-safe.internal' }
  s.source           = { :path => '.' }

  s.ios.deployment_target = '15.0'

  # Static archive produced by: cargo build --release --target aarch64-apple-ios
  s.vendored_libraries = 'target/aarch64-apple-ios/release/libautonomous_swarm_core.a'
  s.source_files = 'ios/*.swift'
  s.public_header_files = 'include/autonomous_swarm_core.h'
  s.header_mappings_dir = 'include'

  s.pod_target_xcconfig = {
    'STRIP_INSTALLED_PRODUCT' => 'YES',
    'DEPLOYMENT_POSTPROCESSING' => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386'
  }
end
