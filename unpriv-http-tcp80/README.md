!!! Disclaimer !!!

- The authors do not have any responsibility and/or liability for how you will use this information and the source code!
- Everything that anyone can find in this repository is only for educational and research purposes, and the authors have no responsibility for how you will use the data found.

A simple HTTP server that binds on port 80 using unprivileged user account with a few features.

netsh http show urlacl

    Reserved URL            : http://+:80/Temporary_Listen_Addresses/
        User: \Everyone
            Listen: Yes
            Delegate: No

Features:

- binds to /Temporary_Listen_Addresses/random-string
- suitable to use with execute-assembly (CS)
- status and shutdown: GET /status and GET /shutdown
- simple code exec: GET /command?"COMMAND"
- code exec with parameters: POST /apic, parameter: lang
- file download: GET /file?FILENAME
- URI path is randomized to avoid issues when unintentionally forgetting to call shutdown
- status pages contains usage examples


Compilation example:

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\unpriv-http-tcp80-v0.3.exe C:\unpriv-http-tcp80-v0.3.cs

Usage example:

- C:\unpriv-http-tcp80-v0.3.exe

Changelog:

- Version 0.1
    - bind to /Temporary_Listen_Addresses/random-string
    - suitable to use with execute-assembly (CS)
    - status and shutdown
    - simple cmd exec
    - file download
- Version 0.2
    - POST cmd exec /apic and parameter lang="dir C:\"
- Version 0.3
    - available commands usage on the status page
    - updated file download

CREDITS:

- File download inspired by: https://gist.githubusercontent.com/zezba9000/04054e3128e6af413e5bc8002489b2fe/raw/6bd6c8f992e895b9840f945819ca647f8f889616/HTTPServer.cs

