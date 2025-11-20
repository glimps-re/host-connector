package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	szFileListHeader1  = "   Date      Time    Attr         Size   Compressed  Name"
	sfFileListHeader2  = "------------------- ----- ------------ ------------  ------------------------"
	szFileListFooter   = "------------------- ----- ------------ ------------  ------------------------"
	szDateTimePrefix   = 0
	szDateTimeSize     = 19
	szAttrPrefix       = 1
	szAttrSize         = 5
	szSizePrefix       = 1
	szSizeSize         = 12
	szCompressedPrefix = 1
	szCompressedSize   = 12
	szNamePrefix       = 2
	szMinLineSize      = szDateTimePrefix + szDateTimeSize + szAttrPrefix + szAttrSize + szSizePrefix + szSizeSize + szCompressedPrefix + szCompressedSize + szNamePrefix
	sevenZipMaxFile    = 200
)

type SevenZipFileAttr int

const (
	Directory SevenZipFileAttr = iota
	ReadOnly
	Hidden
	System
	Archive
)

type extractorConfig struct {
	MaxFileSize          int      `mapstructure:"max_file_size,omitempty"`          // Max size per extracted file in bytes
	MaxExtractedElements int      `mapstructure:"max_extracted_elements,omitempty"` // Max number of files to extract
	DefaultPasswords     []string `mapstructure:"default_passwords,omitempty"`      // Default passwords for encrypted archives
}

type FileProperties struct {
	Name           string `json:"name"`
	Date           string `json:"date"`
	IsDirectory    bool   `json:"is_directory"`
	IsHidden       bool   `json:"is_hidden"`
	Size           int    `json:"size"`
	CompressedSize int    `json:"compressed_size"`
}

type listResult struct {
	files        []FileProperties
	passwordUsed string
}

type extractResult struct {
	extractedFiles []ExtractedFile
	ignoredFiles   []string
	symlinkFiles   []string
	passwordUsed   string
}

type ExtractedFile struct {
	Path                 string `json:"path"`
	ArchivePath          string `json:"archive_path"`
	Size                 int    `json:"size"`
	LastModificationDate string `json:"last_modification_date"`
}

type sevenZipExtract struct {
	config       extractorConfig
	sevenZipPath string
	tmpSevenZip  bool
	tOption      bool
}

var (
	ErrInvalidPassword   = errors.New("invalid password")
	ErrUnsupportedFormat = errors.New("unsupported format")
	ErrFileNotFound      = errors.New("file not found")
)

func newSevenZipExtract(config extractorConfig, sevenZipPath string, tOption bool) (sze *sevenZipExtract) {
	return &sevenZipExtract{
		config:       config,
		sevenZipPath: sevenZipPath,
		tOption:      tOption,
	}
}

func (sze *sevenZipExtract) list(archivePath string, passwords []string, files []string) (archiveContent listResult, err error) {
	var commonArgs []string

	if sze.tOption {
		commonArgs = append(commonArgs, "-t*")
	}
	commonArgs = append(commonArgs, "--", "l", archivePath)

	allPasswords := []string{""}
	allPasswords = append(allPasswords, sze.config.DefaultPasswords...)
	allPasswords = append(allPasswords, passwords...)

	out := ""
PASSWORD_LOOP:
	for _, pwd := range allPasswords {
		total := len(files)
		listedFiles := 0
		for {
			from := listedFiles
			to := min(total, from+sevenZipMaxFile)
			args := append(commonArgs, files[from:to]...) //nolint:gocritic //ok
			out, _, err = sze.run(pwd, args)
			switch {
			case err == nil:
				archiveContent.passwordUsed = pwd
			case errors.Is(err, errSevenZipRecoverable):
				defer func(recoverableError error) {
					if err != nil {
						err = errors.Join(err, recoverableError)
					}
				}(err)
				err = nil
			case errors.Is(err, ErrInvalidPassword):
				continue PASSWORD_LOOP
			default:
				return
			}

			filesProps, errParse := parse7ZListingOutput(out)
			if errParse != nil {
				err = errParse
				return
			}
			archiveContent.files = append(archiveContent.files, filesProps...)

			listedFiles = to
			if listedFiles >= total {
				break PASSWORD_LOOP
			}
		}
	}
	if err != nil {
		return
	}
	return
}

func (sze *sevenZipExtract) extract(archivePath string, extractLocation string, passwords []string, files []string) (extraction extractResult, err error) {
	// we do not extract the all archive at once for security reasons
	// first list files then extract one by one
	archiveContent, err := sze.list(archivePath, passwords, files)
	if err != nil {
		return
	}
	filesToExtract := []string{}
	skippedFiles := []string{}
	for _, file := range archiveContent.files {
		if len(files) > 0 && !slices.Contains(files, file.Name) {
			continue
		}
		if file.Size > sze.config.MaxFileSize || len(filesToExtract) >= sze.config.MaxExtractedElements {
			skippedFiles = append(skippedFiles, file.Name)
			continue
		}
		filesToExtract = append(filesToExtract, file.Name)
	}

	slices.Sort(filesToExtract)
	filesToExtract = slices.Compact(filesToExtract)
	extraction.ignoredFiles = slices.Compact(skippedFiles)

	if len(filesToExtract) == 0 {
		return
	}

	var commonArgs []string
	if sze.tOption {
		commonArgs = append(commonArgs, "-t*")
	}
	commonArgs = append(commonArgs, "-aou", "-o"+extractLocation, "-y", "--", "x", archivePath)

	allPasswords := []string{""}
	allPasswords = append(allPasswords, sze.config.DefaultPasswords...)
	allPasswords = append(allPasswords, passwords...)

	var symLinkFiles []string

PASSWORD_LOOP:
	for _, pwd := range allPasswords {
		total := len(filesToExtract)
		listedFiles := 0
		for {
			from := listedFiles
			to := min(total, from+sevenZipMaxFile)
			args := append(commonArgs, filesToExtract[from:to]...) //nolint:gocritic //ok
			_, symLinkFiles, err = sze.run(pwd, args)
			switch {
			case err == nil:
				extraction.passwordUsed = pwd
			case errors.Is(err, ErrInvalidPassword):
				rmErr := os.RemoveAll(extractLocation)
				if rmErr != nil {
					err = rmErr
					return
				}
				mkdErr := os.MkdirAll(extractLocation, 0o750)
				if mkdErr != nil {
					err = mkdErr
					return
				}
				continue PASSWORD_LOOP
			case errors.Is(err, errSevenZipRecoverable):
				defer func(recoverableError error) {
					if err != nil {
						err = errors.Join(err, recoverableError)
					}
				}(err)
				err = nil
			default:
				return
			}
			extraction.symlinkFiles = append(extraction.symlinkFiles, symLinkFiles...)
			listedFiles = to
			if listedFiles >= total {
				break PASSWORD_LOOP
			}
		}

	}
	if err != nil {
		return
	}

	err = filepath.WalkDir(extractLocation, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Error("error listing directory", slog.String("error", err.Error()), slog.String("path", path))
			return err
		}
		if d.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(extractLocation, path)
		if err != nil {
			return err
		}
		err = extraction.update(path, relPath)
		if err != nil {
			return err
		}
		return nil
	})
	return
}

func (sze *sevenZipExtract) run(password string, args []string) (out string, symLinkFiles []string, err error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var cmd *exec.Cmd
	var argsPwd []string
	if password == "" {
		argsPwd = append([]string{"-p-"}, args...)
	} else {
		argsPwd = append([]string{"-P" + password}, args...)
	}
	cmd = exec.CommandContext(context.Background(), sze.sevenZipPath, argsPwd...) //nolint:gosec // args are handled on our side
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmdErr := cmd.Run()
	symLinkFiles, err = handleSevenZipError(cmdErr, strings.ToValidUTF8(stderr.String(), ""))
	if err != nil {
		return
	}
	out = stdout.String()
	return
}

var errSevenZipRecoverable = errors.New("recoverable sevenzip error")

func handleSevenZipError(sevenZipErr error, stderr string) (symLinkFiles []string, err error) {
	switch {
	case sevenZipErr != nil:
		err = errors.Join(sevenZipErr, errors.New(stderr))
		return
	case stderr == "":
	case strings.Contains(stderr, "Headers Error") ||
		strings.Contains(stderr, "There are some data after the end of the payload data") ||
		strings.Contains(stderr, "ERROR: Data Error") ||
		strings.Contains(stderr, "Unexpected end of archive"):
		err = errors.Join(errSevenZipRecoverable, errors.New(stderr))
	case strings.Contains(stderr, "Wrong password"):
		err = ErrInvalidPassword
	case strings.Contains(stderr, "Dangerous link path was ignored") || strings.Contains(stderr, "Dangerous symbolic link path was ignored"):
		symLinkFiles = parseSymlinkError(stderr)
	case strings.Contains(stderr, "Cannot open the file as archive"):
		err = ErrUnsupportedFormat
	case strings.Contains(stderr, "No such file or directory"):
		err = ErrFileNotFound
	default:
		err = errors.Join(sevenZipErr, errors.New(stderr))
		logger.Error("7z unsupported error", slog.String("retrieved error", stderr), slog.String("returned error", err.Error()))
	}
	return
}

const dateFormat7z = "2006-01-02 15:04:05"

func parse7ZFileListLine(line string) (content FileProperties, err error) {
	// From https://github.com/ip7z/7zip/blob/5b39dc76f1bc82f941d5c800ab9f34407a06b53a/CPP/7zip/UI/Console/List.cpp//L195
	// The line is composed of 5 fields of fixed size with a space prefix, in this order:
	//  - Date Time, 19 characters, no prefix,
	//  - Attr, 5 characters, one space prefix,
	//  - Size, 12 characters, one space prefix,
	//  - Compressed size, 12 characters, one space prefix,
	//  - Name, 24 characters, 2 spaces prefix.
	//
	// Date, Size and Compressed can be missing, in this case, the matching field contains only spaces.
	if len(line) < szMinLineSize {
		err = errors.New("unable to parse 7z output: line is smaller than expected")
		return
	}

	// datetime
	dateTimeStr := ""
	dateTime, errParse := time.ParseInLocation(dateFormat7z, strings.Trim(line[szDateTimePrefix:szDateTimePrefix+szDateTimeSize], " "), time.UTC)
	if errParse == nil {
		dateTimeStr = dateTime.UTC().Format(time.RFC3339)
	}
	line = line[szDateTimePrefix+szDateTimeSize:]

	// Attributes are, in this order :
	//  - 'D' for directory, or '.',
	//  - 'R' for read-only, or '.',
	//  - 'H' for hidden, or '.',
	//  - 'S' for system, or '.',
	//  - 'A' for archive, or '.'.
	// The only interesting information is hidden
	hidden := false
	directory := false
	attrStr := strings.Trim(line[szAttrPrefix:szAttrPrefix+szAttrSize], " ")
	line = line[szAttrPrefix+szAttrSize:]
	if strings.Contains(attrStr, "D") {
		directory = true
	}
	if strings.Contains(attrStr, "H") {
		hidden = true
	}

	// size
	sizeStr := strings.Trim(line[szSizePrefix:szSizePrefix+szSizeSize], " ")
	size, errConv := strconv.Atoi(sizeStr)
	if errConv != nil {
		size = -1
	}
	line = line[szSizePrefix+szSizeSize:]

	// compressed size
	compressedStr := strings.Trim(line[szCompressedPrefix:szCompressedPrefix+szCompressedSize], " ")
	compressed, errConv := strconv.Atoi(compressedStr)
	if errConv != nil {
		compressed = -1
	}
	line = line[szCompressedPrefix+szCompressedSize:]

	// file name
	nameStr := line[szNamePrefix:]

	content = FileProperties{
		Name:           nameStr,
		Date:           dateTimeStr,
		IsDirectory:    directory,
		IsHidden:       hidden,
		Size:           size,
		CompressedSize: compressed,
	}
	return
}

const buffSize = 64 * 1024

func parse7ZListingOutput(stdout string) (files []FileProperties, err error) {
	headerFound := false

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	buf := make([]byte, 0, buffSize)
	scanner.Buffer(buf, buffSize)
	for scanner.Scan() {
		line := scanner.Text()
		if line == szFileListHeader1 {
			headerFound = true
			break
		}
	}

	if !headerFound {
		logger.Error("unable to parse 7z output: file list header not found")
		return
	}

	scanner.Scan()
	if scanner.Text() != sfFileListHeader2 {
		logger.Error("unable to parse 7z output: unexpected line after file list header")
		return
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == szFileListFooter {
			break
		}
		var obj FileProperties
		obj, err = parse7ZFileListLine(line)
		if err != nil {
			return
		}
		if !obj.IsDirectory {
			files = append(files, obj)
		}
	}

	err = scanner.Err()
	if err != nil {
		logger.Error("unable to parse 7z output: error while reading output")
		return
	}
	return
}

func parseSymlinkError(stderr string) (symlinkFiles []string) {
	symlinkFiles = []string{}
	for line := range strings.SplitSeq(stderr, "\n") {
		if line == "" {
			continue
		}
		sanitized := strings.ReplaceAll(line, "ERROR: Dangerous link path was ignored : ", "")
		sanitized = strings.ReplaceAll(sanitized, "ERROR: Dangerous symbolic link path was ignored : ", "")
		sanitized = strings.Split(sanitized, " : ")[0]
		symlinkFiles = append(symlinkFiles, sanitized)
	}
	return
}

func (ec *extractResult) update(filePath string, archivePath string) (err error) {
	if slices.ContainsFunc(ec.extractedFiles, func(ef ExtractedFile) bool {
		return ef.Path == filePath
	}) {
		return
	}

	var fi fs.FileInfo
	fi, err = os.Lstat(filePath)
	if err != nil {
		logger.Error("unable to get stats on file", slog.String("file", filePath), slog.String("error", err.Error()))
		return
	}

	if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		ec.symlinkFiles = append(ec.symlinkFiles, filePath)
		errRm := os.Remove(filePath)
		if errRm != nil {
			logger.Warn("could not remove extracted symlink", slog.String("error", errRm.Error()), slog.String("path", filePath))
		}
		return
	}

	ec.extractedFiles = append(ec.extractedFiles, ExtractedFile{
		Path:                 filePath,
		ArchivePath:          archivePath,
		Size:                 int(fi.Size()),
		LastModificationDate: fi.ModTime().UTC().Format(time.RFC3339),
	})

	// Ensure that user has read permission on the file, add it otherwise
	var f *os.File
	f, err = os.Open(filepath.Clean(filePath))
	switch {
	case err == nil:
		if errClose := f.Close(); errClose != nil {
			logger.Error("failed closing file", slog.String("error", errClose.Error()), slog.String("path", f.Name()))
		}
	case errors.Is(err, os.ErrPermission):
		err = os.Chmod(filePath, 0o400)
		if err != nil {
			logger.Error("could not add read permission to file", slog.String("error", err.Error()), slog.String("path", filePath))
			return
		}
	default:
		logger.Error("unable to open file", slog.String("error", err.Error()), slog.String("path", filePath))
		return
	}
	return
}
