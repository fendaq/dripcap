if($env:APPVEYOR_REPO_TAG_NAME -ne $null){
  cd ../dripcap2
  $env:NO_WPCAP = ""
  yarn
  gulp build
  # workaround for https://github.com/dripcap/dripcap/issues/15
  wget https://raw.githubusercontent.com/Swaven/riot/cfb3bb2d6da73059f06b0379a6f91bd32f350935/lib/server/index.js -OutFile .build\node_modules\riot\lib\server\index.js
  gulp out
  gulp win32
  mv .builtapp\Dripcap-win32-x64 .builtapp\Dripcap
  Compress-Archive -Path .builtapp\Dripcap -DestinationPath ..\dripcap\dripcap-windows-amd64.zip
}
