# HTTP Fuzzer

Fuzzer of HTTP(s) virtual hosts (subdomains). Determine virtual host by comparing response by Jaccard Index algorithm.

Features:
 - Do not resolve DNS.
 - SNI/Host brute forcing of subdomains.
 - Multithreaded and asynchronous
 - Determine virtual host by HTTP `Status Code` and `Content`

## Build
```shell
gradlew build
```

## Run
```shell
java -jar build/libs/http-fuzzer-1.0-SNAPSHOT.jar --target-ip <TARGET_IP> --base-domain <DOMAIN_FOR_FUZZING>
```

Example:
```shell
java -jar build/libs/http-fuzzer-1.0-SNAPSHOT.jar --target-ip 64.233.162.100 --base-domain google.com --dictionary-file dictionaries/alexaTop1mAXFRcommonSubdomains.txt
```

You need to provide dictionary of sub-domains. For example you can use: https://github.com/fuzzdb-project/fuzzdb/raw/master/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt (used by default).
