package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/cyberdelia/lzo"
)

var (
	uncompress = flag.Bool("d", false, "Decompress.")
	level      = flag.Int("l", 3, "Compression level.")
)

func decompress(path string) error {
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	decompressor, err := lzo.NewReader(input)
	if err != nil {
		return err
	}
	output, err := os.Create(decompressor.Name)
	if err != nil {
		return err
	}
	_, err = io.Copy(output, decompressor)
	if err != nil {
		return err
	}
	return nil
}

func compress(level int, path string) error {
	if level > lzo.BestCompression {
		level = lzo.BestCompression
	} else if level < lzo.BestSpeed {
		level = lzo.BestSpeed
	} else {
		level = lzo.DefaultCompression
	}
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	output, err := os.Create(path + ".lzo")
	if err != nil {
		return err
	}
	compressor, err := lzo.NewWriterLevel(output, level)
	defer compressor.Close()
	compressor.Name = input.Name()
	if err != nil {
		return err
	}
	_, err = io.Copy(compressor, input)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	log.SetFlags(0)

	flag.Parse()

	path := flag.Arg(0)
	if path == "" {
		flag.Usage()
		os.Exit(1)
	}

	var err error
	if *uncompress == true {
		err = decompress(path)
	} else {
		err = compress(*level, path)
	}
	if err != nil {
		log.Println("lzop:", err)
	}
}
