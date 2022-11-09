# uri-parser

## Usage

```bash
$ go get github.com/um7a/uri-parser@v0.0.1
```

```go
package main

import (
	"fmt"

	urip "github.com/um7a/uri-parser"
)

func main() {
  data := []byte("https://user:pass@example.com:443/path1/path2?key1=value1&key2=value2#key3=value3&key4=value4")
  uri, err := urip.Parse(data)
  if err != nil {
    fmt.Println(err.Error())
    return
  }
  fmt.Printf("uri       : %s\n", uri)
  fmt.Printf("scheme    : %s\n", uri.Scheme)
  fmt.Printf("authority : %s\n", uri.GetAuthority())
  fmt.Printf("user-info : %s\n", uri.UserInfo)
  fmt.Printf("host      : %s\n", uri.Host)
  fmt.Printf("port      : %s\n", uri.Port)
  fmt.Printf("path      : %s\n", uri.Path)
  fmt.Printf("query     : %s\n", uri.Query)
  fmt.Printf("fragment  : %s\n", uri.Fragment)
}
```

```
$ go run main.go
uri       : https://user:pass@example.com:443/path1/path2?key1=value1&key2=value2#key3=value3&key4=value4
scheme    : https
authority : user:pass@example.com:443
user-info : user:pass
host      : example.com
port      : 443
path      : /path1/path2
query     : key1=value1&key2=value2
fragment  : key3=value3&key4=value4
```
