package main

import (
	"errors"
	"log/slog"
	"slices"
	"testing"
)

func Test_handleSevenZipError(t *testing.T) {
	sevenZipErr := errors.New("exit status 2 (test)")
	type args struct {
		sevenZipErr error
		stderr      string
		paths       []string
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
				stderr:      "ERROR: Wrong password : a.txt",
			},
			wantErr:         true,
			wantSpecificErr: ErrInvalidPassword,
		},
		{
			name: "ko cannot open as archive",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: archive.zip : Cannot open the file as archive",
				paths:       []string{"archive.zip"},
			},
			wantErr:         true,
			wantSpecificErr: ErrUnsupportedFormat,
		},
		{
			name: "ko file not found",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: errno=2 : No such file or directory\narchive.zip",
			},
			wantErr:         true,
			wantSpecificErr: ErrFileNotFound,
		},
		{
			name: "ko headers error recoverable",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: Headers Error : a.txt",
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
				stderr:      "ERRORS:\nUnexpected end of archive",
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
			name: "ko not an archive, the 7z way for a file with an archive extension",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: fake.7z : fake.7z\nOpen ERROR: Cannot open the file as [7z] archive\nERRORS:\nIs not archive",
				paths:       []string{"fake.7z"},
			},
			wantErr:         true,
			wantSpecificErr: ErrUnsupportedFormat,
		},
		{
			name: "ko the path repeated by 7z, with the line that says why",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: archive.7z : archive.7z\nOpen ERROR: Cannot open the file as [7z] archive\n\nERRORS:\nUnexpected end of archive\n",
				paths:       []string{"archive.7z"},
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
		},
		{
			name: "ko the path repeated by 7z, with nothing that says why, is the raw error",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: archive.7z : archive.7z\n",
				paths:       []string{"archive.7z"},
			},
			wantErr:         true,
			wantSpecificErr: sevenZipErr,
		},
		{
			name: "ko a member named like a password error is no password error",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: CRC Failed : Wrong password",
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
		},
		{
			name: "ko a member named like a link error is no refused link",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: CRC Failed : Dangerous link path was ignored",
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
		},
		{
			name: "ko a member named like the not-an-archive error",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: CRC Failed : Cannot open the file as archive",
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
		},
		{
			name: "ko an archive named like a password error is no password error",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: Wrong password.7z : Wrong password.7z\nOpen ERROR: Cannot open the file as [7z] archive\nERRORS:\nUnexpected end of archive",
				paths:       []string{"Wrong password.7z"},
			},
			wantErr: true,
		},
		{
			name: "ko an archive named like the not-an-archive error",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: CRC Failed : Cannot open the file as archive.zip",
				paths:       []string{"Cannot open the file as archive.zip"},
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
		},
		{
			name: "ko a refused link does not hide another error",
			args: args{
				sevenZipErr: sevenZipErr,
				stderr:      "ERROR: Dangerous link path was ignored : l : /etc/passwd\nERROR: CRC Failed : b.txt",
			},
			wantErr:         true,
			wantSpecificErr: errSevenZipRecoverable,
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
			gotSymLinkFiles, err := handleSevenZipError(tt.args.sevenZipErr, tt.args.stderr, slog.New(slog.DiscardHandler), tt.args.paths...)

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
