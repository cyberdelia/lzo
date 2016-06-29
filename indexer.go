package lzo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"io"
	"os"
	"time"
)

// Header metadata about the compressed file.
// This header is exposed as the fields of the Writer and Reader structs.
type IndexHeader struct {
	ModTime                    time.Time
	Name                       string
	flags                      uint32
	version                    uint16
	libraryVersion             uint16
	method                     uint8
	num_compressed_checksums   uint
	num_decompressed_checksums uint
}

// A Reader is an io.Reader that can be read to retrieve
// uncompressed data from a lzop-format compressed file.
type Indexer struct {
	IndexHeader
	r       io.Reader
	f       *os.File
	buf     [512]byte
	hist    []byte
	indexes []int64
	adler32 hash.Hash32
	crc32   hash.Hash32
	err     error
}

// NewReader creates a new Reader reading the given reader.
func NewIndexer(f *os.File) (*Indexer, error) {
	z := new(Indexer)
	z.adler32 = adler32.New()
	z.crc32 = crc32.NewIEEE()
	z.f = f
	z.r = io.TeeReader(f, io.MultiWriter(z.adler32, z.crc32))
	if err := z.readHeader(); err != nil {
		return nil, err
	}
	return z, nil
}

func (z *Indexer) read(data interface{}) error {
	return binary.Read(z.r, binary.BigEndian, data)
}

func (z *Indexer) readHeader() error {
	// Read and check magic
	if _, err := io.ReadFull(z.r, z.buf[0:len(lzoMagic)]); err != nil {
		return err
	}
	if !bytes.Equal(z.buf[0:len(lzoMagic)], lzoMagic) {
		return errors.New("lzo: invalid header")
	}
	z.crc32.Reset()
	z.adler32.Reset()
	// Read version
	if err := z.read(&z.version); err != nil {
		return err
	}
	if version < 0x0900 {
		return errors.New("lzo: invalid header")
	}
	// Read library version needed to extract
	if err := z.read(&z.libraryVersion); err != nil {
		return err
	}
	if version >= 0x0940 {
		if err := z.read(&z.libraryVersion); err != nil {
			return err
		}
		if z.libraryVersion > z.version {
			return errors.New("lzo: incompatible version")
		}
		if z.libraryVersion < 0x0900 {
			return errors.New("lzo: invalid header")
		}
	}
	// Read method
	if err := z.read(&z.method); err != nil {
		return err
	}
	// Read level
	if version >= 0x0940 {
		var level uint8
		if err := z.read(&level); err != nil {
			return err
		}
	}
	// Read flags
	if err := z.read(&z.flags); err != nil {
		return err
	}
	// Read filters
	if z.flags&flagFilter != 0 {
		var filters uint32
		if err := z.read(&filters); err != nil {
			return err
		}
	}
	// Read num_compressed_checksums
	z.num_compressed_checksums = 0
	if z.flags&flagAdler32C != 0 {
		z.num_compressed_checksums += 1
	}
	if z.flags&flagCRC32C != 0 {
		z.num_compressed_checksums += 1
	}

	// Read num_decompressed_checksums
	z.num_decompressed_checksums = 0
	if z.flags&flagAdler32D != 0 {
		z.num_decompressed_checksums += 1
	}
	if z.flags&flagCRC32D != 0 {
		z.num_decompressed_checksums += 1
	}

	// Read mode
	var mode uint32
	if err := z.read(&mode); err != nil {
		return err
	}
	// Read modification times
	var modTime, modTimeHigh uint32
	if err := z.read(&modTime); err != nil {
		return err
	}
	z.ModTime = time.Unix(int64(modTime), 0)
	// Read mod time high
	if version >= 0x0940 {
		if err := z.read(&modTimeHigh); err != nil {
			return err
		}
	}
	if version < 0x0120 {
		z.ModTime = time.Unix(0, 0)
	}
	// Read name
	var l uint8
	if err := z.read(&l); err != nil {
		return err
	}
	if l > 0 {
		if _, err := io.ReadFull(z.r, z.buf[0:l]); err != nil {
			return err
		}
		z.Name = string(z.buf[0:l])
	}
	// Read and check header checksum
	var checksum uint32
	if z.flags&flagCRC32 != 0 {
		checksum = z.crc32.Sum32()
		z.crc32.Reset()
	} else {
		checksum = z.adler32.Sum32()
		z.adler32.Reset()
	}
	var checksumHeader uint32
	if err := z.read(&checksumHeader); err != nil {
		return err
	}
	if checksumHeader != checksum {
		return errors.New("lzo: invalid header")
	}
	if z.method <= 0 {
		return errors.New("lzo: incompatible method")
	}
	return nil
}

func (z *Indexer) findBlock() error {
	// Read uncompressed block size
	var block_start int64
	block_start, z.err = z.f.Seek(0, os.SEEK_CUR)
	if z.err != nil {
		return z.err
	}

	var dstLen uint32
	z.err = z.read(&dstLen)
	if z.err != nil {
		return z.err
	}
	if dstLen == 0 {
		z.err = io.EOF
		return z.err
	}
	// Read compressed block size
	var srcLen uint32
	z.err = z.read(&srcLen)
	if z.err != nil {
		return z.err
	}
	if srcLen <= 0 || srcLen > dstLen {
		z.err = errors.New("lzo: data corruption")
		return z.err
	}
	// Read checksum of uncompressed block
	var dstChecksum uint32
	if z.flags&flagAdler32D != 0 {
		z.err = z.read(&dstChecksum)
		if z.err != nil {
			return z.err
		}
	}
	if z.flags&flagCRC32D != 0 {
		z.err = z.read(&dstChecksum)
		if z.err != nil {
			return z.err
		}
	}
	// Read checksum of compressed block
	var srcChecksum uint32
	if z.flags&flagAdler32C != 0 {
		if srcLen < dstLen {
			z.err = z.read(&srcChecksum)
			if z.err != nil {
				return z.err
			}
		} else {
			srcChecksum = dstChecksum
		}
	}
	if z.flags&flagCRC32C != 0 {
		if srcLen < dstLen {
			z.err = z.read(&srcChecksum)
			if z.err != nil {
				return z.err
			}
		} else {
			srcChecksum = dstChecksum
		}
	}
	z.indexes = append(z.indexes, block_start)
	z.f.Seek(int64(srcLen), os.SEEK_CUR)
	return nil
}

func CreateIndex(filename string) error {
	index_file_name := filename + ".index"

	lzofile, err := os.Open(filename)
	defer lzofile.Close()
	if err != nil {
		return err
	}
	indexfile, err := os.Create(index_file_name)
	defer indexfile.Close()
	if err != nil {
		return err
	}

	indexer, err := NewIndexer(lzofile)
	defer indexer.Close()
	for {
		indexer.findBlock()
		if indexer.err != nil {
			break
		}
	}
	if indexer.err == io.EOF {
		for _, num := range indexer.indexes {
			//tmp := make([]byte,8)
			//binary.BigEndian.PutUint64(tmp, uint64(num))
			//indexfile.Write(tmp)
			binary.Write(indexfile, binary.BigEndian, num)
		}
	} else {
		return indexer.err
	}
	return nil
}

// Close closes the Reader. It does not close the underlying io.Reader.
func (z *Indexer) Close() error {
	if z.err == io.EOF {
		return nil
	}
	return z.err
}
