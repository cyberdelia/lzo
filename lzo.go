package lzo

/*
#cgo LDFLAGS: -llzo2
#include <lzo/lzo1x.h>

static int lzo_initialize(void) { return lzo_init(); }
static int lzo1x_1_mem_compress() { return LZO1X_1_MEM_COMPRESS; }
static int lzo1x_999_mem_compress() { return LZO1X_999_MEM_COMPRESS; }
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"io"
	"time"
	"unsafe"
)

const (
	BestSpeed          = 1
	BestCompression    = 9
	DefaultCompression = -1
	version            = 0x1030
	flagAdler32D       = 1 << 0
	flagAdler32C       = 1 << 1
	flagStdin          = 1 << 2
	flagStdout         = 1 << 3
	flagNameDefault    = 1 << 4
	flagDosish         = 1 << 5
	flagExtra          = 1 << 6
	flagGmtDiff        = 1 << 7
	flagCRC32D         = 1 << 8
	flagCRC32C         = 1 << 9
	flagMultipart      = 1 << 10
	flagFilter         = 1 << 11
	flagCRC32          = 1 << 12
	flagPath           = 1 << 13
	flagMask           = 1 << 14
)

var (
	lzoMagic   = []byte{0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a}
	ErrHeader  = errors.New("lzo: invalid header")
	ErrVersion = errors.New("lzo: incompatible version")
	ErrMethod  = errors.New("lzo: incompatible method")
	ErrCorrupt = errors.New("lzo: data corruption")
)

func init() {
	if err := C.lzo_initialize(); err != 0 {
		panic("lzo: can't initialize")
	}
}

type Header struct {
	Version        uint32
	LibraryVersion uint32
	ExtractVersion uint32
	Method         byte
	Level          byte
	Flags          uint32
	Filter         uint32
	Mode           uint32
	ModTimeLow     time.Time
	ModTimeHigh    time.Time
	Checksum       uint32
	Name           string
}

type Reader struct {
	Header
	r       io.Reader
	buf     [512]byte
	hist	[]byte
	adler32 hash.Hash32
	crc32   hash.Hash32
	err     error
}

func NewReader(r io.Reader) (*Reader, error) {
	z := new(Reader)
	z.r = r
	z.adler32 = adler32.New()
	z.crc32 = crc32.NewIEEE()
	if err := z.readHeader(); err != nil {
		return nil, err
	}
	return z, nil
}

func (z *Reader) readHeader() error {
	_, err := io.ReadFull(z.r, z.buf[0:len(lzoMagic)])
	if err != nil {
		return err
	}
	if !bytes.Equal(z.buf[0:len(lzoMagic)], lzoMagic) {
		return ErrHeader
	}
	z.Version, err = z.read16()
	if err != nil {
		return err
	}
	if z.Version < 0x0900 {
		return ErrHeader
	}
	z.LibraryVersion, err = z.read16()
	if err != nil {
		return err
	}
	if z.Version >= 0x0940 {
		z.ExtractVersion, err = z.read16()
		if err != nil {
			return err
		}
		if z.ExtractVersion > version {
			return ErrVersion
		}
		if z.ExtractVersion < 0x0900 {
			return ErrHeader
		}
	}
	z.Method, err = z.read8()
	if err != nil {
		return err
	}
	if z.Version >= 0x0940 {
		z.Level, err = z.read8()
		if err != nil {
			return err
		}
	}
	z.Flags, err = z.read32()
	if err != nil {
		return err
	}
	if z.Flags&flagFilter != 0 {
		z.Filter, err = z.read32()
		if err != nil {
			return err
		}
	}
	z.Mode, err = z.read32()
	if err != nil {
		return err
	}
	if z.Flags&flagStdin != 0 {
		z.Mode = 0
	}
	modTimeLow, err := z.read32()
	if err != nil {
		return err
	}
	z.ModTimeLow = time.Unix(int64(modTimeLow), 0)
	if z.Version >= 0x0940 {
		modTimeHigh, err := z.read32()
		if err != nil {
			return err
		}
		z.ModTimeHigh = time.Unix(int64(modTimeHigh), 0)
	}
	if z.Version < 0x0120 {
		z.ModTimeLow = time.Unix(0, 0)
		z.ModTimeHigh = time.Unix(0, 0)
	}
	l, err := z.read8()
	if err != nil {
		return err
	}
	if l > 0 {
		_, err := io.ReadFull(z.r, z.buf[0:l])
		if err != nil {
			return err
		}
		z.adler32.Write(z.buf[0:l])
		z.crc32.Write(z.buf[0:l])
		z.Name = string(z.buf[0:l])
	}
	var checksum uint32
	if z.Flags&flagCRC32 != 0 {
		checksum = z.crc32.Sum32()
		z.crc32.Reset()
	} else {
		checksum = z.adler32.Sum32()
		z.adler32.Reset()
	}
	z.Checksum, err = z.read32()
	if err != nil {
		return err
	}
	if z.Checksum != checksum {
		return ErrHeader
	}
	if z.Method <= 0 {
		return ErrMethod
	}
	return nil
}

func (z *Reader) read8() (byte, error) {
	_, err := io.ReadFull(z.r, z.buf[0:1])
	if err != nil {
		return 0, err
	}
	z.adler32.Write(z.buf[0:1])
	z.crc32.Write(z.buf[0:1])
	return z.buf[0], nil
}

func (z *Reader) read16() (uint32, error) {
	_, err := io.ReadFull(z.r, z.buf[0:2])
	if err != nil {
		return 0, err
	}
	z.adler32.Write(z.buf[0:2])
	z.crc32.Write(z.buf[0:2])
	return uint32(z.buf[1])<<0 | uint32(z.buf[0])<<8, nil
}

func (z *Reader) read32() (uint32, error) {
	_, err := io.ReadFull(z.r, z.buf[0:4])
	if err != nil {
		return 0, err
	}
	z.adler32.Write(z.buf[0:4])
	z.crc32.Write(z.buf[0:4])
	return uint32(z.buf[3]) | uint32(z.buf[2])<<8 | uint32(z.buf[1])<<16 | uint32(z.buf[0])<<24, nil
}

func (z *Reader) nextBlock() {
	// Read uncompressed block size
	var dstLen uint32
	dstLen, z.err = z.read32()
	if z.err != nil {
		return
	}
	if dstLen == 0 {
		z.err = io.EOF
		return
	}
	// Read compressed block size
	var srcLen uint32
	srcLen, z.err = z.read32()
	if z.err != nil {
		return
	}
	if srcLen <= 0 || srcLen > dstLen {
		z.err = ErrCorrupt
		return
	}
	// Read checksum of uncompressed block
	var dstChecksum uint32
	if z.Flags&flagAdler32D != 0 {
		dstChecksum, z.err = z.read32()
		if z.err != nil {
			return
		}
	}
	if z.Flags&flagCRC32D != 0 {
		dstChecksum, z.err = z.read32()
		if z.err != nil {
			return
		}
	}
	// Read checksum of compressed block
	var srcChecksum uint32
	if z.Flags&flagAdler32C != 0 {
		if srcLen < dstLen {
			srcChecksum, z.err = z.read32()
			if z.err != nil {
				return
			}
		} else {
			srcChecksum = dstChecksum
		}
	}
	if z.Flags&flagCRC32C != 0 {
		if srcLen < dstLen {
			srcChecksum, z.err = z.read32()
			if z.err != nil {
				return
			}
		} else {
			srcChecksum = dstChecksum
		}
	}
	// Read block
	block := make([]byte, srcLen)
	_, z.err = io.ReadFull(z.r, block)
	if z.err != nil {
		return
	}
	// Verify compressed block checksum
	if z.Flags&flagAdler32C != 0 {
		z.adler32.Reset()
		z.adler32.Write(block)
		if srcChecksum != z.adler32.Sum32() {
			z.err = ErrCorrupt
			return
		}
	}
	if z.Flags&flagCRC32C != 0 {
		z.crc32.Reset()
		z.crc32.Write(block)
		if srcChecksum != z.crc32.Sum32() {
			z.err = ErrCorrupt
			return
		}
	}
	// Decompress
	data := make([]byte, dstLen)
	if srcLen < dstLen {
		_, z.err = lzoDecompress(block, data)
		if z.err != nil {
			return
		}
	} else {
		copy(data, block)
	}
	// Verify uncompressed block checksum
	if z.Flags&flagAdler32D != 0 {
		z.adler32.Reset()
		z.adler32.Write(data)
		if dstChecksum != z.adler32.Sum32() {
			z.err = ErrCorrupt
			return
		}
	}
	if z.Flags&flagCRC32D != 0 {
		z.crc32.Reset()
		z.crc32.Write(data)
		if dstChecksum != z.crc32.Sum32() {
			z.err = ErrCorrupt
			return
		}
	}
	// Add block to our history
	z.hist = append(z.hist, data...)
}

func (z *Reader) Read(p []byte) (int, error) {
	for {
		if len(z.hist) > 0 {
			n := copy(p, z.hist)
			z.hist = z.hist[n:]
			return n, nil
		}
		if z.err != nil {
			return 0, z.err
		}
		z.nextBlock()
	}
}

func (z *Reader) Close() error {
	if z.err == io.EOF {
		return nil
	}
	return z.err
}

func lzoDecompress(src []byte, dst []byte) (int, error) {
	dstLen := len(dst)
	err := C.lzo1x_decompress_safe((*C.uchar)(unsafe.Pointer(&src[0])), C.lzo_uint(len(src)),
		(*C.uchar)(unsafe.Pointer(&dst[0])), (*C.lzo_uint)(unsafe.Pointer(&dstLen)), nil)
	if err != 0 {
		return 0, fmt.Errorf("lzo: errno %d", err)
	}
	return dstLen, nil
}

type Writer struct {
	w          io.Writer
	level      int
	err        error
	compressor func([]byte) ([]byte, error)
}

func NewWriter(w io.Writer) *Writer {
	z, _ := NewWriterLevel(w, DefaultCompression)
	return z
}

func NewWriterLevel(w io.Writer, level int) (*Writer, error) {
	if level < DefaultCompression || level > BestCompression {
		return nil, fmt.Errorf("lzo: invalid compression level: %d", level)
	}
	return &Writer{
		w:     w,
		level: level,
	}, nil
}

func (z *Writer) Write(p []byte) (int, error) {
	if z.err != nil {
		return 0, z.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	var compressed []byte
	if z.compressor == nil {
		if z.level == BestCompression {
			z.compressor = func(src []byte) ([]byte, error) {
				return lzoCompress(src, lzoCompressBest)
			}
		} else {
			z.compressor = func(src []byte) ([]byte, error) {
				return lzoCompress(src, lzoCompressSpeed)
			}
		}
	}
	compressed, z.err = z.compressor(p)
	z.w.Write(compressed)
	return len(compressed), z.err
}

func lzoCompress(src []byte, compress func([]byte, []byte, *int) C.int) ([]byte, error) {
	dst_size := 0
	dst := make([]byte, lzoDestinationSize(len(src)))
	err := compress(src, dst, &dst_size)
	if err != 0 {
		return nil, fmt.Errorf("lzo: errno %d", err)
	}
	return dst[0:dst_size], nil
}

func lzoDestinationSize(n int) int {
	return (n + n/16 + 64 + 3)
}

func lzoCompressSpeed(src []byte, dst []byte, dst_size *int) C.int {
	wrkmem := make([]byte, int(C.lzo1x_1_mem_compress()))
	return C.lzo1x_1_compress((*C.uchar)(unsafe.Pointer(&src[0])), C.lzo_uint(len(src)),
		(*C.uchar)(unsafe.Pointer(&dst[0])), (*C.lzo_uint)(unsafe.Pointer(dst_size)),
		unsafe.Pointer(&wrkmem[0]))
}

func lzoCompressBest(src []byte, dst []byte, dst_size *int) C.int {
	wrkmem := make([]byte, int(C.lzo1x_999_mem_compress()))
	return C.lzo1x_999_compress((*C.uchar)(unsafe.Pointer(&src[0])), C.lzo_uint(len(src)),
		(*C.uchar)(unsafe.Pointer(&dst[0])), (*C.lzo_uint)(unsafe.Pointer(dst_size)),
		unsafe.Pointer(&wrkmem[0]))
}
