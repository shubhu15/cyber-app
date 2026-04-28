package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type storage interface {
	Save(uploadID int64, filename string, src io.Reader) (string, error)
	Open(fileRef string) (io.ReadCloser, error)
}

type localDiskStorage struct {
	root string
}

func newLocalDiskStorage(root string) storage {
	return &localDiskStorage{root: root}
}

func (s *localDiskStorage) Save(uploadID int64, filename string, src io.Reader) (string, error) {
	if err := os.MkdirAll(s.root, 0o755); err != nil {
		return "", err
	}

	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		ext = ".log"
	}

	fileRef := fmt.Sprintf("%d%s", uploadID, ext)
	absolutePath := filepath.Join(s.root, fileRef)

	dst, err := os.Create(absolutePath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", err
	}

	return fileRef, nil
}

func (s *localDiskStorage) Open(fileRef string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(s.root, fileRef))
}
