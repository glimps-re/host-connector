package main

import (
	"errors"
	"slices"
	"testing"
)

func Test_handleSevenZipError(t *testing.T) {
	sevenZipErr := errors.New("exit status 2 (test)")

	type args struct {
		sevenZipErr error
		stderr      string
	}
	tests := []struct {
		name             string
		args             args
		wantSymLinkFiles []string
		wantErr          bool
		wantSpecificErr  error
	}{
		{
			name: "ko sevenZipErr with empty stderr",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "",
			},
			wantErr:         true,
			wantSpecificErr: sevenZipErr,
		},
		{
			name: "ko wrong password",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "Wrong password",
			},
			wantErr:         true,
			wantSpecificErr: ErrInvalidPassword,
		},
		{
			name: "ko cannot open as archive",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "Cannot open the file as archive",
			},
			wantErr:         true,
			wantSpecificErr: ErrUnsupportedFormat,
		},
		{
			name: "ko file not found",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "No such file or directory",
			},
			wantErr:         true,
			wantSpecificErr: ErrFileNotFound,
		},
		{
			name: "ko headers error recoverable",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "Headers Error",
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
		},
		{
			name: "ko data error recoverable",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: Data Error",
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
		},
		{
			name: "ko unexpected end recoverable",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "Unexpected end of archive",
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
		},
		{
			name: "ko data after payload recoverable",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "There are some data after the end of the payload data",
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
		},
		{
			name: "ko unknown error",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "some unknown 7z error",
			},
			wantErr:         true,
			wantSpecificErr: sevenZipErr,
		},
		{
			name: "ok no error",
			args: args{
				sevenZipErr: nil,
				stderr:      "",
			},
		},
		{
			name: "ok no error with stderr content",
			args: args{
				sevenZipErr: nil,
				stderr:      "some warning message",
			},
		},
		{
			name: "ok dangerous link path ignored",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: Dangerous link path was ignored : etc/os-release : ../usr/lib/os-release\nERROR: Dangerous link path was ignored : etc/mtab : ../proc/self/mounts",
			},
			wantSymLinkFiles: []string{"etc/os-release", "etc/mtab"},
		},
		{
			name: "ok dangerous link via another link ignored",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: Dangerous link via another link was ignored : usr/bin/pidof : sbin/killall5\nERROR: Dangerous link via another link was ignored : usr/bin/systemd : lib/systemd/systemd",
			},
			wantSymLinkFiles: []string{"usr/bin/pidof", "usr/bin/systemd"},
		},
		{
			name: "ok dangerous symbolic link path ignored",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: Dangerous symbolic link path was ignored : some/path : ../target",
			},
			wantSymLinkFiles: []string{"some/path"},
		},
		{
			name: "ok mixed dangerous link errors",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: Dangerous link path was ignored : path1 : ../target1\nERROR: Dangerous link via another link was ignored : path2 : target2\nERROR: Dangerous symbolic link path was ignored : path3 : ../target3",
			},
			wantSymLinkFiles: []string{"path1", "path2", "path3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSymLinkFiles, err := handleSevenZipError(tt.args.sevenZipErr, tt.args.stderr)

			if (err != nil) != tt.wantErr {
				t.Errorf("handleSevenZipError() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantSpecificErr != nil && !errors.Is(err, tt.wantSpecificErr) {
				t.Errorf("handleSevenZipError() error = %v, wantSpecificErr %v", err, tt.wantSpecificErr)
				return
			}

			if err != nil {
				return
			}

			slices.Sort(gotSymLinkFiles)
			slices.Sort(tt.wantSymLinkFiles)
			if !slices.Equal(gotSymLinkFiles, tt.wantSymLinkFiles) {
				t.Errorf("handleSevenZipError() symLinkFiles = %v, want %v", gotSymLinkFiles, tt.wantSymLinkFiles)
			}
		})
	}
}

func Test_calculateEffectiveZipBombSizes(t *testing.T) {
	type args struct {
		files       []FileProperties
		maxFileSize int
	}
	tests := []struct {
		name                    string
		args                    args
		wantTotalSize           int64
		wantTotalCompressedSize int64
	}{
		{
			name: "ok empty files",
			args: args{
				files:       []FileProperties{},
				maxFileSize: 100,
			},
			wantTotalSize:           0,
			wantTotalCompressedSize: 0,
		},
		{
			name: "ok all files below max size",
			args: args{
				files: []FileProperties{
					{Name: "file1.txt", Size: 10, CompressedSize: 5},
					{Name: "file2.txt", Size: 20, CompressedSize: 8},
					{Name: "file3.txt", Size: 30, CompressedSize: 12},
				},
				maxFileSize: 100,
			},
			wantTotalSize:           60,
			wantTotalCompressedSize: 25,
		},
		{
			name: "ok all files above max size",
			args: args{
				files: []FileProperties{
					{Name: "big1.bin", Size: 500_000_000, CompressedSize: 45_000_000},
					{Name: "big2.bin", Size: 600_000_000, CompressedSize: 50_000_000},
				},
				maxFileSize: 100_000_000,
			},
			wantTotalSize:           0,
			wantTotalCompressedSize: 0,
		},
		{
			name: "ok mixed files some above max size",
			args: args{
				files: []FileProperties{
					{Name: "big1.bin", Size: 500_000_000, CompressedSize: 45_000_000},
					{Name: "small1.txt", Size: 10_000_000, CompressedSize: 1_000_000},
					{Name: "big2.bin", Size: 600_000_000, CompressedSize: 50_000_000},
					{Name: "small2.txt", Size: 20_000_000, CompressedSize: 2_000_000},
				},
				maxFileSize: 100_000_000,
			},
			wantTotalSize:           30_000_000,
			wantTotalCompressedSize: 3_000_000,
		},
		{
			name: "ok file exactly at max size included",
			args: args{
				files: []FileProperties{
					{Name: "exact.bin", Size: 100, CompressedSize: 40},
					{Name: "small.txt", Size: 50, CompressedSize: 20},
				},
				maxFileSize: 100,
			},
			wantTotalSize:           150,
			wantTotalCompressedSize: 60,
		},
		{
			name: "ok file just above max size excluded",
			args: args{
				files: []FileProperties{
					{Name: "over.bin", Size: 101, CompressedSize: 40},
					{Name: "small.txt", Size: 50, CompressedSize: 20},
				},
				maxFileSize: 100,
			},
			wantTotalSize:           50,
			wantTotalCompressedSize: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTotalSize, gotTotalCompressedSize := calculateEffectiveZipBombSizes(tt.args.files, tt.args.maxFileSize)
			if gotTotalSize != tt.wantTotalSize {
				t.Errorf("calculateEffectiveZipBombSizes() totalSize = %v, want %v", gotTotalSize, tt.wantTotalSize)
			}
			if gotTotalCompressedSize != tt.wantTotalCompressedSize {
				t.Errorf("calculateEffectiveZipBombSizes() totalCompressedSize = %v, want %v", gotTotalCompressedSize, tt.wantTotalCompressedSize)
			}
		})
	}
}
