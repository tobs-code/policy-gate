'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function nativeLibraryName() {
  switch (process.platform) {
    case 'win32':
      return 'firewall_napi.dll';
    case 'darwin':
      return 'libfirewall_napi.dylib';
    default:
      return 'libfirewall_napi.so';
  }
}

function main() {
  execFileSync('cargo', ['build', '-p', 'firewall-napi'], {
    stdio: 'inherit',
  });

  const source = path.join(process.cwd(), 'target', 'debug', nativeLibraryName());
  const destinationDir = path.join(process.cwd(), 'native');
  const destination = path.join(destinationDir, 'index.node');

  if (!fs.existsSync(source)) {
    throw new Error(`Native library not found: ${source}`);
  }

  fs.mkdirSync(destinationDir, { recursive: true });
  fs.copyFileSync(source, destination);

  console.log(`native module copied to ${destination}`);
}

main();
