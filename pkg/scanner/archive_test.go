package scanner

import (
	"errors"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/google/go-cmp/cmp"
)

func Test_archiveStatusHandler_addInnerFileResult(t *testing.T) {
	type fields struct {
		archiveNotFound bool
		initialAnalyzed int
		total           int
	}
	type args struct {
		filename string
		result   datamodel.Result
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantFinished bool
		wantOk       bool
		wantMalware  bool
	}{
		{
			name:   "ko archive not found",
			fields: fields{archiveNotFound: true},
			args: args{
				filename: "test.txt",
				result:   datamodel.Result{},
			},
		},
		{
			name: "ok file added, not finished",
			fields: fields{
				initialAnalyzed: 0,
				total:           3,
			},
			args: args{
				filename: "file1.txt",
				result:   datamodel.Result{Malware: false},
			},
			wantOk: true,
		},
		{
			name: "ok file added, archive finished",
			fields: fields{
				initialAnalyzed: 1,
				total:           2,
			},
			args: args{
				filename: "file2.txt",
				result:   datamodel.Result{Malware: false},
			},
			wantFinished: true,
			wantOk:       true,
		},
		{
			name: "ok malware result merged",
			fields: fields{
				initialAnalyzed: 0,
				total:           2,
			},
			args: args{
				filename: "malware.exe",
				result: datamodel.Result{
					Malware:  true,
					Malwares: []string{"Trojan.Test"},
				},
			},
			wantOk:      true,
			wantMalware: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newArchiveStatusHandler()

			var archiveID string
			if !tt.fields.archiveNotFound {
				archiveID = a.addStatus(archiveStatus{
					started:         true,
					finished:        false,
					archiveLocation: "/path/to/archive.zip",
					result: datamodel.Result{
						SHA256:   "archive-sha256",
						Location: "/path/to/archive.zip",
					},
					analyzed: tt.fields.initialAnalyzed,
					total:    tt.fields.total,
				})
			} else {
				archiveID = "nonexistent-id"
			}

			gotFinished, gotOk := a.addInnerFileResult(archiveID, tt.args.filename, tt.args.result)

			if gotOk != tt.wantOk {
				t.Errorf("addInnerFileResult() ok = %v, want %v", gotOk, tt.wantOk)
				return
			}
			if gotFinished != tt.wantFinished {
				t.Errorf("addInnerFileResult() finished = %v, want %v", gotFinished, tt.wantFinished)
			}

			if !tt.wantOk {
				return
			}

			status, _, ok := a.getArchiveStatus(archiveID, false)
			if !ok {
				t.Errorf("archive status should exist after addInnerFileResult")
				return
			}
			if status.analyzed != tt.fields.initialAnalyzed+1 {
				t.Errorf("analyzed = %d, want %d", status.analyzed, tt.fields.initialAnalyzed+1)
			}
			if status.result.Malware != tt.wantMalware {
				t.Errorf("result.Malware = %v, want %v", status.result.Malware, tt.wantMalware)
			}
			if tt.wantMalware {
				if _, exists := status.result.MaliciousSubfiles[tt.args.filename]; !exists {
					t.Errorf("MaliciousSubfiles should contain %s", tt.args.filename)
				}
			}
		})
	}
}

func Test_mergeResult(t *testing.T) {
	type args struct {
		baseResult    datamodel.Result
		resultToMerge datamodel.Result
		filename      string
	}
	tests := []struct {
		name       string
		args       args
		wantResult datamodel.Result
	}{
		{
			name: "ok merge with non-malware file",
			args: args{
				baseResult: datamodel.Result{
					SHA256:   "base-sha256",
					Location: "/archive.zip",
				},
				resultToMerge: datamodel.Result{
					Malware:        false,
					AnalyzedVolume: 100,
				},
				filename: "clean.txt",
			},
			wantResult: datamodel.Result{
				SHA256:             "base-sha256",
				Location:           "/archive.zip",
				Malware:            false,
				AnalyzedVolume:     100,
				TotalExtractedFile: 1,
				MaliciousSubfiles:  map[string]datamodel.Result{},
			},
		},
		{
			name: "ok merge with malware file",
			args: args{
				baseResult: datamodel.Result{
					SHA256:   "base-sha256",
					Location: "/archive.zip",
				},
				resultToMerge: datamodel.Result{
					Malware:        true,
					Malwares:       []string{"Trojan.Test"},
					MalwareReason:  datamodel.MalwareDetected,
					AnalyzedVolume: 200,
					Score:          80,
				},
				filename: "malware.exe",
			},
			wantResult: datamodel.Result{
				SHA256:             "base-sha256",
				Location:           "/archive.zip",
				Malware:            true,
				Malwares:           []string{"Trojan.Test"},
				MalwareReason:      datamodel.MalwareDetected,
				AnalyzedVolume:     200,
				Score:              80,
				TotalExtractedFile: 1,
				MaliciousSubfiles: map[string]datamodel.Result{
					"malware.exe": {
						Malware:        true,
						Malwares:       []string{"Trojan.Test"},
						MalwareReason:  datamodel.MalwareDetected,
						AnalyzedVolume: 200,
						Score:          80,
						Location:       "/archive.zip",
					},
				},
			},
		},
		{
			name: "ok malware flag propagation",
			args: args{
				baseResult: datamodel.Result{
					SHA256:   "base-sha256",
					Location: "/archive.zip",
					Malware:  false,
				},
				resultToMerge: datamodel.Result{
					Malware:       true,
					MalwareReason: datamodel.MalwareDetected,
				},
				filename: "virus.exe",
			},
			wantResult: datamodel.Result{
				SHA256:             "base-sha256",
				Location:           "/archive.zip",
				Malware:            true,
				MalwareReason:      datamodel.MalwareDetected,
				TotalExtractedFile: 1,
				MaliciousSubfiles: map[string]datamodel.Result{
					"virus.exe": {
						Malware:       true,
						MalwareReason: datamodel.MalwareDetected,
						Location:      "/archive.zip",
					},
				},
			},
		},
		{
			name: "ok malwares list merge without duplicates",
			args: args{
				baseResult: datamodel.Result{
					SHA256:        "base-sha256",
					Location:      "/archive.zip",
					Malware:       true,
					Malwares:      []string{"Trojan.A", "Trojan.B"},
					MalwareReason: datamodel.MalwareDetected,
				},
				resultToMerge: datamodel.Result{
					Malware:       true,
					Malwares:      []string{"Trojan.B", "Trojan.C"},
					MalwareReason: datamodel.MalwareDetected,
				},
				filename: "another.exe",
			},
			wantResult: datamodel.Result{
				SHA256:             "base-sha256",
				Location:           "/archive.zip",
				Malware:            true,
				Malwares:           []string{"Trojan.A", "Trojan.B", "Trojan.C"},
				MalwareReason:      datamodel.MalwareDetected,
				TotalExtractedFile: 1,
				MaliciousSubfiles: map[string]datamodel.Result{
					"another.exe": {
						Malware:       true,
						Malwares:      []string{"Trojan.B", "Trojan.C"},
						MalwareReason: datamodel.MalwareDetected,
						Location:      "/archive.zip",
					},
				},
			},
		},
		{
			name: "ok MalwareReason priority MalwareDetected over AnalysisError",
			args: args{
				baseResult: datamodel.Result{
					MalwareReason: datamodel.AnalysisError,
				},
				resultToMerge: datamodel.Result{
					MalwareReason: datamodel.MalwareDetected,
					Malware:       true,
				},
				filename: "file.exe",
			},
			wantResult: datamodel.Result{
				Malware:            true,
				MalwareReason:      datamodel.MalwareDetected,
				TotalExtractedFile: 1,
				MaliciousSubfiles: map[string]datamodel.Result{
					"file.exe": {
						Malware:       true,
						MalwareReason: datamodel.MalwareDetected,
					},
				},
			},
		},
		{
			name: "ok MalwareReason priority AnalysisError over TooBig",
			args: args{
				baseResult: datamodel.Result{
					MalwareReason: datamodel.TooBig,
				},
				resultToMerge: datamodel.Result{
					MalwareReason: datamodel.AnalysisError,
				},
				filename: "file.txt",
			},
			wantResult: datamodel.Result{
				MalwareReason:      datamodel.AnalysisError,
				TotalExtractedFile: 1,
				MaliciousSubfiles:  map[string]datamodel.Result{},
			},
		},
		{
			name: "ok volume accumulation",
			args: args{
				baseResult: datamodel.Result{
					AnalyzedVolume: 100,
					FilteredVolume: 50,
				},
				resultToMerge: datamodel.Result{
					AnalyzedVolume: 200,
					FilteredVolume: 30,
				},
				filename: "file.txt",
			},
			wantResult: datamodel.Result{
				AnalyzedVolume:     300,
				FilteredVolume:     80,
				TotalExtractedFile: 1,
				MaliciousSubfiles:  map[string]datamodel.Result{},
			},
		},
		{
			name: "ok score takes max value",
			args: args{
				baseResult: datamodel.Result{
					Score: 50,
				},
				resultToMerge: datamodel.Result{
					Score: 80,
				},
				filename: "file.txt",
			},
			wantResult: datamodel.Result{
				Score:              80,
				TotalExtractedFile: 1,
				MaliciousSubfiles:  map[string]datamodel.Result{},
			},
		},
		{
			name: "ok score keeps base when higher",
			args: args{
				baseResult: datamodel.Result{
					Score: 90,
				},
				resultToMerge: datamodel.Result{
					Score: 60,
				},
				filename: "file.txt",
			},
			wantResult: datamodel.Result{
				Score:              90,
				TotalExtractedFile: 1,
				MaliciousSubfiles:  map[string]datamodel.Result{},
			},
		},
		{
			name: "ok TotalExtractedFile accumulates from sub-archive",
			args: args{
				baseResult: datamodel.Result{
					SHA256:             "base-sha256",
					Location:           "/archive.zip",
					TotalExtractedFile: 2,
				},
				resultToMerge: datamodel.Result{
					Malware:            true,
					MalwareReason:      datamodel.MalwareDetected,
					TotalExtractedFile: 3,
				},
				filename: "sub-archive.zip",
			},
			wantResult: datamodel.Result{
				SHA256:             "base-sha256",
				Location:           "/archive.zip",
				Malware:            true,
				MalwareReason:      datamodel.MalwareDetected,
				TotalExtractedFile: 6,
				MaliciousSubfiles: map[string]datamodel.Result{
					"sub-archive.zip": {
						Malware:            true,
						MalwareReason:      datamodel.MalwareDetected,
						TotalExtractedFile: 3,
						Location:           "/archive.zip",
					},
				},
			},
		},
		{
			name: "ok TotalExtractedFile recursive depth 3",
			args: args{
				baseResult: datamodel.Result{
					SHA256:   "root-sha256",
					Location: "/root.zip",
				},
				resultToMerge: datamodel.Result{
					Malware:            true,
					MalwareReason:      datamodel.MalwareDetected,
					TotalExtractedFile: 5,
					MaliciousSubfiles: map[string]datamodel.Result{
						"level2.zip": {
							Malware:            true,
							TotalExtractedFile: 2,
						},
					},
				},
				filename: "level1.zip",
			},
			wantResult: datamodel.Result{
				SHA256:             "root-sha256",
				Location:           "/root.zip",
				Malware:            true,
				MalwareReason:      datamodel.MalwareDetected,
				TotalExtractedFile: 6,
				MaliciousSubfiles: map[string]datamodel.Result{
					"level1.zip": {
						Malware:            true,
						MalwareReason:      datamodel.MalwareDetected,
						TotalExtractedFile: 5,
						Location:           "/root.zip",
						MaliciousSubfiles: map[string]datamodel.Result{
							"level2.zip": {
								Malware:            true,
								TotalExtractedFile: 2,
							},
						},
					},
				},
			},
		},
		{
			name: "ok ErrorSubfiles merge with file error",
			args: args{
				baseResult: datamodel.Result{
					SHA256:   "base-sha256",
					Location: "/archive.zip",
				},
				resultToMerge: datamodel.Result{
					Error:          errors.New("connection refused (test)"),
					AnalyzedVolume: 100,
				},
				filename: "failed.exe",
			},
			wantResult: datamodel.Result{
				SHA256:             "base-sha256",
				Location:           "/archive.zip",
				AnalyzedVolume:     100,
				TotalExtractedFile: 1,
				MaliciousSubfiles:  map[string]datamodel.Result{},
				ErrorSubfiles: map[string]string{
					"failed.exe": "connection refused (test)",
				},
			},
		},
		{
			name: "ok ErrorSubfiles accumulates multiple errors",
			args: args{
				baseResult: datamodel.Result{
					SHA256:   "base-sha256",
					Location: "/archive.zip",
					ErrorSubfiles: map[string]string{
						"first.exe": "first error (test)",
					},
					TotalExtractedFile: 1,
					MaliciousSubfiles:  map[string]datamodel.Result{},
				},
				resultToMerge: datamodel.Result{
					Error: errors.New("second error (test)"),
				},
				filename: "second.exe",
			},
			wantResult: datamodel.Result{
				SHA256:             "base-sha256",
				Location:           "/archive.zip",
				TotalExtractedFile: 2,
				MaliciousSubfiles:  map[string]datamodel.Result{},
				ErrorSubfiles: map[string]string{
					"first.exe":  "first error (test)",
					"second.exe": "second error (test)",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult := mergeResult(tt.args.baseResult, tt.args.resultToMerge, tt.args.filename)

			if diff := cmp.Diff(gotResult, tt.wantResult); diff != "" {
				t.Errorf("mergeResult() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}
