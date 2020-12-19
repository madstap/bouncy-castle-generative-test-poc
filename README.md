# Generative testing bouncy castle vulnerability (CVE-2020-28052)

## Running the tests

Test the vulnerable versions (defaults to 1.66)
```
$ clojure -M:test
$ clojure -M:test:v1.65
```

Test the versions before the vuln and after the patch (1.67)

```
$ clojure -M:test:v1.64
$ clojure -M:test:patched
```


## Links

https://www.bleepingcomputer.com/news/security/bouncy-castle-crypto-authentication-bypass-vulnerability-revealed/

https://twitter.com/saleemrash1d/status/1339998265899687937

https://github.com/bcgit/bc-java/issues/627
