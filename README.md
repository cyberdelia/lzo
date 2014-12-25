# lzo

lzo implements reading and writing of lzo format compressed files for Go, following lzop format.
It uses the lzo C library underneath.

## Installation

Download and install :

```
$ go get github.com/cyberdelia/lzo
```

Add it to your code :

```go
import "github.com/cyberdelia/lzo"
```

## Command line tool

Download and install:

```console
$ go get github.com/cyberdelia/lzo/cmd/lzop
```

Compress and decompress:

```console
$ lzop testdata/pg135.txt
$ lzop -d testdata/pg135.txt.lzo
```
