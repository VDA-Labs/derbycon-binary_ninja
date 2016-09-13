# derbycon-binary_ninja
Repo contains code for our DerbyCon 2016 talk comparing Binary Ninja and IDA Pro.

The binary was de-obfuscated (ie dumped). It uses process hallowing to inject code into explorer.exe.

All of the API calls are dynamically resolved, function at sub_401728 uses the PEB to located DLLs in memory based on a hash.

sub_40175E then uses the address resolved for the module to resolve the needed functions.

The python script will comment the modules loaded - working on resolving APIs
