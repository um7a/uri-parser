# uri-parser

## Usage

```bash
$ go get github.com/um7a/uri-parser@latest
```

```go
package main

import (
  "fmt"

  urip "github.com/um7a/uri-parser"
)

func main() {
	data := []byte("https://user:pass@example.com:443/path1/path2?key1=value1&key2=value2#key3=value3&key4=value4")
  uri := urip.Parse(data)
  fmt.Println(uri)
}
```
