package filesystem

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/go-cmp/cmp"
)

type S3ClientMock struct {
	HeadObjectMock    func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObjectMock     func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadBucketMock    func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	ListObjectsV2Mock func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	DeleteObjectMock  func(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	PutObjectMock     func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	CreateBucketMock  func(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error)
	CopyObjectMock    func(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error)
}

func (m *S3ClientMock) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if m.HeadObjectMock != nil {
		return m.HeadObjectMock(ctx, params, optFns...)
	}
	panic("S3ClientMock.HeadObject() not implemented in current test")
}

func (m *S3ClientMock) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.GetObjectMock != nil {
		return m.GetObjectMock(ctx, params, optFns...)
	}
	panic("S3ClientMock.GetObject() not implemented in current test")
}

func (m *S3ClientMock) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if m.HeadBucketMock != nil {
		return m.HeadBucketMock(ctx, params, optFns...)
	}
	panic("S3ClientMock.HeadBucket() not implemented in current test")
}

func (m *S3ClientMock) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if m.ListObjectsV2Mock != nil {
		return m.ListObjectsV2Mock(ctx, params, optFns...)
	}
	panic("S3ClientMock.ListObjectsV2() not implemented in current test")
}

func (m *S3ClientMock) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if m.DeleteObjectMock != nil {
		return m.DeleteObjectMock(ctx, params, optFns...)
	}
	panic("S3ClientMock.DeleteObject() not implemented in current test")
}

func (m *S3ClientMock) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.PutObjectMock != nil {
		return m.PutObjectMock(ctx, params, optFns...)
	}
	panic("S3ClientMock.PutObject() not implemented in current test")
}

func (m *S3ClientMock) CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	if m.CreateBucketMock != nil {
		return m.CreateBucketMock(ctx, params, optFns...)
	}
	panic("S3ClientMock.CreateBucket() not implemented in current test")
}

func (m *S3ClientMock) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	if m.CopyObjectMock != nil {
		return m.CopyObjectMock(ctx, params, optFns...)
	}
	panic("S3ClientMock.CopyObject() not implemented in current test")
}

func TestStreamingReadSeekCloser_Read(t *testing.T) {
	type fields struct {
		// get object mock
		getObjectResp  string
		getObjectError error

		bucket string
		key    string
		size   int64
		pos    int64
	}
	type args struct {
		bufSize int
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantRange string // bytes=start-end
		wantN     int
		wantErr   bool
		wantPos   int64
	}{
		{
			name: "successful read from start",
			fields: fields{
				bucket:        "test-bucket",
				key:           "test-key",
				size:          100,
				pos:           0,
				getObjectResp: "0123456789",
			},
			args: args{
				bufSize: 10,
			},
			wantRange: "bytes=0-9",
			wantN:     10,
			wantErr:   false,
			wantPos:   10,
		},
		{
			name: "read from middle position",
			fields: fields{
				bucket:        "test-bucket",
				key:           "test-key",
				size:          100,
				pos:           50,
				getObjectResp: "0123456789",
			},
			args: args{
				bufSize: 10,
			},
			wantRange: "bytes=50-59",
			wantN:     10,
			wantErr:   false,
			wantPos:   60,
		},
		{
			name: "read at end of file",
			fields: fields{
				bucket: "test-bucket",
				key:    "test-key",
				size:   100,
				pos:    100,
			},
			args: args{
				bufSize: 10,
			},
			wantN:   0,
			wantErr: false,
			wantPos: 100,
		},
		{
			name: "read near end of file",
			fields: fields{
				getObjectResp: "bytes=95-99",
				bucket:        "test-bucket",
				key:           "test-key",
				size:          100,
				pos:           95,
			},
			args: args{
				bufSize: 10,
			},
			wantRange: "bytes=95-99",
			wantN:     5,
			wantErr:   false,
			wantPos:   100,
		},
		{
			name: "S3 GetObject error",
			fields: fields{
				getObjectError: errors.New("S3 error"),
				bucket:         "test-bucket",
				key:            "test-key",
				size:           100,
				pos:            0,
			},
			args: args{
				bufSize: 10,
			},
			wantRange: "bytes=0-9",
			wantN:     0,
			wantErr:   true,
			wantPos:   0,
		},
		{
			name: "partial read with UnexpectedEOF at file end",
			fields: fields{
				getObjectResp: "12",
				bucket:        "test-bucket",
				key:           "test-key",
				size:          100,
				pos:           98,
			},
			args: args{
				bufSize: 10,
			},
			wantRange: "bytes=98-99",
			wantN:     2,
			wantErr:   false, // Should handle ErrUnexpectedEOF at file end gracefully
			wantPos:   100,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &S3ClientMock{
				GetObjectMock: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
					if *params.Bucket != tt.fields.bucket {
						t.Errorf("streamingReadSeekCloser.Read() called on bad bucket, got=%s, want=%s", *params.Bucket, tt.fields.bucket)
					}
					if *params.Key != tt.fields.key {
						t.Errorf("streamingReadSeekCloser.Read() called on bad bucket, got=%s, want=%s", *params.Bucket, tt.fields.bucket)
					}
					return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(tt.fields.getObjectResp))}, tt.fields.getObjectError
				},
			}

			r := &streamingReadSeekCloser{
				client: mock,
				bucket: tt.fields.bucket,
				key:    tt.fields.key,
				size:   tt.fields.size,
				pos:    tt.fields.pos,
			}

			buf := make([]byte, tt.args.bufSize)
			gotN, err := r.Read(buf)

			if (err != nil && !errors.Is(err, io.EOF)) != tt.wantErr {
				t.Errorf("streamingReadSeekCloser.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Special case for EOF
			if tt.fields.pos >= tt.fields.size {
				if !errors.Is(err, io.EOF) {
					t.Errorf("streamingReadSeekCloser.Read() expected io.EOF, got %v", err)
				}
			}

			if gotN != tt.wantN {
				t.Errorf("streamingReadSeekCloser.Read() n = %v, want %v", gotN, tt.wantN)
			}

			if r.pos != tt.wantPos {
				t.Errorf("streamingReadSeekCloser.Read() pos = %v, want %v", r.pos, tt.wantPos)
			}
		})
	}
}

func TestStreamingReadSeekCloser_Seek(t *testing.T) {
	type fields struct {
		size int64
		pos  int64
	}
	type args struct {
		offset int64
		whence int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    int64
		wantErr bool
		wantPos int64
	}{
		{
			name: "seek from start",
			fields: fields{
				size: 100,
				pos:  50,
			},
			args: args{
				offset: 25,
				whence: io.SeekStart,
			},
			want:    25,
			wantErr: false,
			wantPos: 25,
		},
		{
			name: "seek from current",
			fields: fields{
				size: 100,
				pos:  50,
			},
			args: args{
				offset: 10,
				whence: io.SeekCurrent,
			},
			want:    60,
			wantErr: false,
			wantPos: 60,
		},
		{
			name: "seek from end",
			fields: fields{
				size: 100,
				pos:  50,
			},
			args: args{
				offset: -10,
				whence: io.SeekEnd,
			},
			want:    90,
			wantErr: false,
			wantPos: 90,
		},
		{
			name: "seek to negative position",
			fields: fields{
				size: 100,
				pos:  50,
			},
			args: args{
				offset: -60,
				whence: io.SeekCurrent,
			},
			want:    0,
			wantErr: true,
			wantPos: 50, // Position should remain unchanged on error
		},
		{
			name: "seek with invalid whence",
			fields: fields{
				size: 100,
				pos:  50,
			},
			args: args{
				offset: 10,
				whence: 999, // Invalid whence value
			},
			want:    0,
			wantErr: true,
			wantPos: 50, // Position should remain unchanged on error
		},
		{
			name: "seek beyond file size",
			fields: fields{
				size: 100,
				pos:  50,
			},
			args: args{
				offset: 200,
				whence: io.SeekStart,
			},
			want:    200,
			wantErr: false,
			wantPos: 200, // Should allow seeking beyond file size
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &streamingReadSeekCloser{
				size: tt.fields.size,
				pos:  tt.fields.pos,
			}

			got, err := r.Seek(tt.args.offset, tt.args.whence)

			if (err != nil) != tt.wantErr {
				t.Errorf("streamingReadSeekCloser.Seek() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("streamingReadSeekCloser.Seek() = %v, want %v", got, tt.want)
			}

			if r.pos != tt.wantPos {
				t.Errorf("streamingReadSeekCloser.Seek() pos = %v, want %v", r.pos, tt.wantPos)
			}
		})
	}
}

func TestStreamingReadSeekCloser_Close(t *testing.T) {
	r := &streamingReadSeekCloser{}

	err := r.Close()
	if err != nil {
		t.Errorf("streamingReadSeekCloser.Close() error = %v, want nil", err)
	}
}

func TestStreamingReadSeekCloser_ConcurrentAccess(t *testing.T) {
	mock := &S3ClientMock{
		GetObjectMock: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
			// Simulate some processing time
			time.Sleep(5 * time.Millisecond)
			return &s3.GetObjectOutput{
				Body: io.NopCloser(strings.NewReader("test data")),
			}, nil
		},
	}

	r := &streamingReadSeekCloser{
		client: mock,
		bucket: "test-bucket",
		key:    "test-key",
		size:   1000,
		pos:    0,
	}

	// Test concurrent reads and seeks
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Start multiple goroutines performing reads and seeks
	for i := range 5 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Perform seek
			offset := int64(id * 10)
			_, err := r.Seek(offset, io.SeekStart)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d seek error: %w", id, err)
				return
			}

			// Perform read
			buf := make([]byte, 5)
			_, err = r.Read(buf)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d read error: %w", id, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}
}

func TestNewStreamingReadSeekCloser(t *testing.T) {
	mock := &S3ClientMock{}
	bucket := "test-bucket"
	key := "test-key"
	size := int64(1024)

	r := newStreamingReadSeekCloser(mock, bucket, key, size)

	if r.client != mock {
		t.Error("client not set correctly")
	}
	if r.bucket != bucket {
		t.Errorf("bucket = %v, want %v", r.bucket, bucket)
	}
	if r.key != key {
		t.Errorf("key = %v, want %v", r.key, key)
	}
	if r.size != size {
		t.Errorf("size = %v, want %v", r.size, size)
	}
	if r.pos != 0 {
		t.Errorf("pos = %v, want 0", r.pos)
	}
}

func TestS3FileSystem_Open(t *testing.T) {
	type fields struct {
		fileSize        int64
		streamThreshold int
		headObjectFail  bool
		getObjectFail   bool
		fileContent     string
	}
	type args struct {
		name string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantData []byte
		wantErr  bool
	}{
		{
			name: "successful small file read",
			fields: fields{
				fileSize:        10,
				streamThreshold: DefaultStreamThreshold,
				fileContent:     "test data",
			},
			args: args{
				name: "bucket/test.txt",
			},
			wantData: []byte("test data"),
			wantErr:  false,
		},
		{
			name:   "error invalid path",
			fields: fields{},
			args: args{
				name: "",
			},
			wantData: nil,
			wantErr:  true,
		},
		{
			name:   "error opening bucket as file",
			fields: fields{},
			args: args{
				name: "bucket",
			},
			wantData: nil,
			wantErr:  true,
		},
		{
			name: "error HeadObject fails",
			fields: fields{
				headObjectFail: true,
			},
			args: args{
				name: "bucket/test.txt",
			},
			wantData: nil,
			wantErr:  true,
		},
		{
			name: "error GetObject fails",
			fields: fields{
				fileSize:      10,
				getObjectFail: true,
			},
			args: args{
				name: "bucket/test.txt",
			},
			wantData: nil,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &S3ClientMock{
				HeadObjectMock: func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
					if tt.fields.headObjectFail {
						return nil, errors.New("head object failed")
					}
					if *params.Bucket != "bucket" || *params.Key != strings.TrimPrefix(tt.args.name, "bucket/") {
						t.Errorf("HeadObject called with unexpected params: bucket=%s, key=%s", *params.Bucket, *params.Key)
					}
					return &s3.HeadObjectOutput{
						ContentLength: aws.Int64(tt.fields.fileSize),
					}, nil
				},
				GetObjectMock: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
					if tt.fields.getObjectFail {
						return nil, errors.New("get object failed")
					}
					if *params.Bucket != "bucket" || *params.Key != strings.TrimPrefix(tt.args.name, "bucket/") {
						t.Errorf("GetObject called with unexpected params: bucket=%s, key=%s", *params.Bucket, *params.Key)
					}
					// For streaming (large files), expect range requests
					if tt.fields.fileSize > int64(tt.fields.streamThreshold) && params.Range == nil {
						return nil, errors.New("expected range request for large file")
					}
					return &s3.GetObjectOutput{
						Body: io.NopCloser(strings.NewReader(tt.fields.fileContent)),
					}, nil
				},
			}

			s := &S3FileSystem{
				client: client,
				config: S3Config{StreamThreshold: tt.fields.streamThreshold},
			}
			gotReader, err := s.Open(t.Context(), tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("S3FileSystem.Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			gotData, err := io.ReadAll(gotReader)
			if err != nil {
				t.Errorf("S3FileSystem.Open() could not read result, err: %v", err)
				return
			}
			if diff := cmp.Diff(tt.wantData, gotData); diff != "" {
				t.Errorf("S3FileSystem.Open() data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestS3FileSystem_Stat(t *testing.T) {
	type fields struct {
		fileSize         int64
		modTime          time.Time
		headObjectFail   bool
		headBucketFail   bool
		listObjectsFail  bool
		isDirectory      bool
		isEmptyDirectory bool
		isBucketOnly     bool
	}
	type args struct {
		name string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantInfo *s3FileInfo
		wantErr  bool
	}{
		{
			name: "ok",
			fields: fields{
				fileSize: 1024,
				modTime:  time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			args: args{
				name: "bucket/test.txt",
			},
			wantInfo: &s3FileInfo{
				name:    "test.txt",
				size:    1024,
				modTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				mode:    0o644,
				isDir:   false,
			},
			wantErr: false,
		},
		{
			name: "ok bucket stat",
			fields: fields{
				isBucketOnly: true,
			},
			args: args{
				name: "bucket",
			},
			wantInfo: &s3FileInfo{
				name:  "bucket",
				size:  0,
				mode:  0o755 | fs.ModeDir,
				isDir: true,
			},
			wantErr: false,
		},
		{
			name: "successful directory stat via ListObjectsV2",
			fields: fields{
				headObjectFail: true,
				isDirectory:    true,
			},
			args: args{
				name: "bucket/folder",
			},
			wantInfo: &s3FileInfo{
				name:  "folder",
				size:  0,
				mode:  0o755 | fs.ModeDir,
				isDir: true,
			},
			wantErr: false,
		},
		{
			name:   "error invalid path",
			fields: fields{},
			args: args{
				name: "",
			},
			wantInfo: nil,
			wantErr:  true,
		},
		{
			name: "error HeadBucket fails for bucket",
			fields: fields{
				isBucketOnly:   true,
				headBucketFail: true,
			},
			args: args{
				name: "bucket",
			},
			wantInfo: nil,
			wantErr:  true,
		},
		{
			name: "error list objects",
			fields: fields{
				headObjectFail:  true,
				listObjectsFail: true,
			},
			args: args{
				name: "bucket/folder",
			},
			wantErr: true,
		},
		{
			name: "error empty prefix",
			fields: fields{
				headObjectFail:   true,
				isEmptyDirectory: true,
			},
			args: args{
				name: "bucket/folder",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &S3ClientMock{
				HeadObjectMock: func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
					if tt.fields.headObjectFail || tt.fields.isBucketOnly {
						return nil, errors.New("not found")
					}
					expectedBucket, expectedKey := "bucket", strings.TrimPrefix(tt.args.name, "bucket/")
					if *params.Bucket != expectedBucket || *params.Key != expectedKey {
						t.Errorf("HeadObject called with unexpected params: bucket=%s, key=%s", *params.Bucket, *params.Key)
					}
					return &s3.HeadObjectOutput{
						ContentLength: aws.Int64(tt.fields.fileSize),
						LastModified:  &tt.fields.modTime,
					}, nil
				},
				HeadBucketMock: func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
					if tt.fields.headBucketFail {
						return nil, errors.New("bucket not found")
					}
					if *params.Bucket != "bucket" {
						t.Errorf("HeadBucket called with unexpected bucket: %s", *params.Bucket)
					}
					return &s3.HeadBucketOutput{}, nil
				},
				ListObjectsV2Mock: func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
					if tt.fields.listObjectsFail {
						return nil, errors.New("list failed")
					}
					if tt.fields.isDirectory {
						return &s3.ListObjectsV2Output{
							Contents: []types.Object{
								{Key: aws.String("folder/file.txt")},
							},
						}, nil
					}
					if tt.fields.isEmptyDirectory {
						return &s3.ListObjectsV2Output{
							Contents: []types.Object{},
						}, nil
					}
					return &s3.ListObjectsV2Output{}, nil
				},
			}

			s := &S3FileSystem{
				client: client,
				config: S3Config{},
			}
			gotInfo, err := s.Stat(t.Context(), tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("S3FileSystem.Stat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Convert to s3FileInfo for comparison
			var got *s3FileInfo
			if gotInfo != nil {
				got = &s3FileInfo{
					name:    gotInfo.Name(),
					size:    gotInfo.Size(),
					modTime: gotInfo.ModTime(),
					mode:    gotInfo.Mode(),
					isDir:   gotInfo.IsDir(),
				}
			}

			if diff := cmp.Diff(tt.wantInfo, got, cmp.AllowUnexported(s3FileInfo{})); diff != "" {
				t.Errorf("S3FileSystem.Stat() info mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestS3FileSystem_Remove(t *testing.T) {
	type fields struct {
		deleteFail bool
	}
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "successful remove",
			fields: fields{},
			args: args{
				path: "bucket/test.txt",
			},
			wantErr: false,
		},
		{
			name:   "error invalid path",
			fields: fields{},
			args: args{
				path: "",
			},
			wantErr: true,
		},
		{
			name:   "error cannot remove bucket",
			fields: fields{},
			args: args{
				path: "bucket",
			},
			wantErr: true,
		},
		{
			name: "error DeleteObject fails",
			fields: fields{
				deleteFail: true,
			},
			args: args{
				path: "bucket/test.txt",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &S3ClientMock{
				DeleteObjectMock: func(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
					if tt.fields.deleteFail {
						return nil, errors.New("delete failed")
					}
					expectedBucket, expectedKey := "bucket", "test.txt"
					if *params.Bucket != expectedBucket || *params.Key != expectedKey {
						t.Errorf("DeleteObject called with unexpected params: bucket=%s, key=%s", *params.Bucket, *params.Key)
					}
					return &s3.DeleteObjectOutput{}, nil
				},
			}

			s := &S3FileSystem{
				client: client,
				config: S3Config{},
			}
			if err := s.Remove(t.Context(), tt.args.path); (err != nil) != tt.wantErr {
				t.Errorf("S3FileSystem.Remove() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3FileSystem_Create(t *testing.T) {
	type fields struct {
		putObjectFail bool
	}
	type args struct {
		name string
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantWriter bool
		wantErr    bool
	}{
		{
			name:   "successful create",
			fields: fields{},
			args: args{
				name: "bucket/test.txt",
			},
			wantWriter: true,
			wantErr:    false,
		},
		{
			name:   "error invalid path",
			fields: fields{},
			args: args{
				name: "",
			},
			wantWriter: false,
			wantErr:    true,
		},
		{
			name:   "error cannot create file without key",
			fields: fields{},
			args: args{
				name: "bucket",
			},
			wantWriter: false,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &S3ClientMock{
				PutObjectMock: func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
					if tt.fields.putObjectFail {
						return nil, errors.New("put object failed")
					}
					// This will be called when writer.Close() is called
					return &s3.PutObjectOutput{}, nil
				},
			}

			s := &S3FileSystem{
				client: client,
				config: S3Config{},
			}
			gotWriter, err := s.Create(t.Context(), tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("S3FileSystem.Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantWriter && gotWriter == nil {
				t.Errorf("S3FileSystem.Create() expected writer, got nil")
			}
			if !tt.wantWriter && gotWriter != nil {
				t.Errorf("S3FileSystem.Create() expected no writer, got %v", gotWriter)
			}
		})
	}
}

func TestS3FileSystem_MkdirAll(t *testing.T) {
	type fields struct {
		headBucketFail            bool
		headBucketNotFound        bool
		createBucketFail          bool
		createBucketAlreadyExists bool
		createBucketExists        bool
		putObjectFail             bool
	}
	type args struct {
		path string
		perm os.FileMode
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "ok",
			fields: fields{},
			args: args{
				path: "bucket/folder",
				perm: 0o755,
			},
			wantErr: false,
		},
		{
			name: "ok create bucket",
			fields: fields{
				headBucketNotFound: true,
			},
			args: args{
				path: "new-bucket",
				perm: 0o755,
			},
			wantErr: false,
		},
		{
			name: "bucket already exists",
			fields: fields{
				createBucketExists: true,
			},
			args: args{
				path: "existing-bucket",
				perm: 0o755,
			},
			wantErr: false, // Should not error on bucket already exists
		},
		{
			name:   "error invalid path",
			fields: fields{},
			args: args{
				path: "",
				perm: 0o755,
			},
			wantErr: true,
		},
		{
			name: "error CreateBucket fails",
			fields: fields{
				headBucketNotFound: true,
				createBucketFail:   true,
			},
			args: args{
				path: "new-bucket",
				perm: 0o755,
			},
			wantErr: true,
		},
		{
			name: "error CreateBucket already exists",
			fields: fields{
				headBucketNotFound:        true,
				createBucketAlreadyExists: true,
			},
			args: args{
				path: "new-bucket",
				perm: 0o755,
			},
		},
		{
			name: "error PutObject fails",
			fields: fields{
				putObjectFail: true,
			},
			args: args{
				path: "bucket/folder",
				perm: 0o755,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &S3ClientMock{
				HeadBucketMock: func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
					if tt.fields.headBucketFail {
						return nil, errors.New("head bucket failed")
					}
					if tt.fields.headBucketNotFound {
						return nil, &types.NoSuchBucket{}
					}
					return &s3.HeadBucketOutput{}, nil
				},
				CreateBucketMock: func(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
					if tt.fields.createBucketFail {
						return nil, errors.New("create bucket failed")
					}
					if tt.fields.createBucketAlreadyExists {
						return nil, &types.BucketAlreadyExists{}
					}
					if tt.fields.createBucketExists {
						return nil, &types.BucketAlreadyExists{}
					}
					expectedBucket := strings.Split(tt.args.path, "/")[0]
					if *params.Bucket != expectedBucket {
						t.Errorf("CreateBucket called with unexpected bucket: %s", *params.Bucket)
					}
					return &s3.CreateBucketOutput{}, nil
				},
				PutObjectMock: func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
					if tt.fields.putObjectFail {
						return nil, errors.New("put object failed")
					}
					expectedBucket := "bucket"
					expectedKey := "folder/"
					if *params.Bucket != expectedBucket || *params.Key != expectedKey {
						t.Errorf("PutObject called with unexpected params: bucket=%s, key=%s", *params.Bucket, *params.Key)
					}
					return &s3.PutObjectOutput{}, nil
				},
			}

			s := &S3FileSystem{
				client: client,
				config: S3Config{},
			}
			if err := s.MkdirAll(t.Context(), tt.args.path, tt.args.perm); (err != nil) != tt.wantErr {
				t.Errorf("S3FileSystem.MkdirAll() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3FileSystem_Rename(t *testing.T) {
	type fields struct {
		copyFail   bool
		deleteFail bool
	}
	type args struct {
		oldPath string
		newPath string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "successful rename",
			fields: fields{},
			args: args{
				oldPath: "bucket/old.txt",
				newPath: "bucket/new.txt",
			},
			wantErr: false,
		},
		{
			name:   "error cannot rename buckets",
			fields: fields{},
			args: args{
				oldPath: "old-bucket",
				newPath: "new-bucket",
			},
			wantErr: true,
		},
		{
			name: "error copy fails",
			fields: fields{
				copyFail: true,
			},
			args: args{
				oldPath: "bucket/old.txt",
				newPath: "bucket/new.txt",
			},
			wantErr: true,
		},
		{
			name: "error delete fails",
			fields: fields{
				deleteFail: true,
			},
			args: args{
				oldPath: "bucket/old.txt",
				newPath: "bucket/new.txt",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &S3ClientMock{
				CopyObjectMock: func(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
					if tt.fields.copyFail {
						return nil, errors.New("copy failed")
					}
					expectedCopySource := tt.args.oldPath
					expectedBucket, expectedKey := "bucket", "new.txt"
					if *params.CopySource != expectedCopySource {
						t.Errorf("CopyObject called with unexpected copy source: %s, want %s", *params.CopySource, expectedCopySource)
					}
					if *params.Bucket != expectedBucket || *params.Key != expectedKey {
						t.Errorf("CopyObject called with unexpected params: bucket=%s, key=%s", *params.Bucket, *params.Key)
					}
					return &s3.CopyObjectOutput{}, nil
				},
				DeleteObjectMock: func(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
					if tt.fields.deleteFail {
						return nil, errors.New("delete failed")
					}
					expectedBucket, expectedKey := "bucket", "old.txt"
					if *params.Bucket != expectedBucket || *params.Key != expectedKey {
						t.Errorf("DeleteObject called with unexpected params: bucket=%s, key=%s", *params.Bucket, *params.Key)
					}
					return &s3.DeleteObjectOutput{}, nil
				},
			}

			s := &S3FileSystem{
				client: client,
				config: S3Config{},
			}
			if err := s.Rename(t.Context(), tt.args.oldPath, tt.args.newPath); (err != nil) != tt.wantErr {
				t.Errorf("S3FileSystem.Rename() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3FileSystem_parsePath(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name       string
		args       args
		wantBucket string
		wantKey    string
		wantErr    bool
	}{
		{
			name:       "bucket and key",
			args:       args{path: "my-bucket/path/to/file.txt"},
			wantBucket: "my-bucket",
			wantKey:    "path/to/file.txt",
			wantErr:    false,
		},
		{
			name:       "bucket only",
			args:       args{path: "my-bucket"},
			wantBucket: "my-bucket",
			wantKey:    "",
			wantErr:    false,
		},
		{
			name:       "bucket with leading slash",
			args:       args{path: "/my-bucket/file.txt"},
			wantBucket: "my-bucket",
			wantKey:    "file.txt",
			wantErr:    false,
		},
		{
			name:       "empty path",
			args:       args{path: ""},
			wantBucket: "",
			wantKey:    "",
			wantErr:    true,
		},
		{
			name:       "only slash",
			args:       args{path: "/"},
			wantBucket: "",
			wantKey:    "",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &S3FileSystem{}
			gotBucket, gotKey, err := s.parsePath(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("S3FileSystem.parsePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotBucket != tt.wantBucket {
				t.Errorf("S3FileSystem.parsePath() gotBucket = %v, want %v", gotBucket, tt.wantBucket)
			}
			if gotKey != tt.wantKey {
				t.Errorf("S3FileSystem.parsePath() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}

type mockFileEntry struct {
	IsDir    bool
	Size     int64
	ModTime  time.Time
	Children map[string]mockFileEntry
}

func TestS3FileSystem_WalkDir(t *testing.T) {
	type fields struct {
		headBucketFail   bool
		headObjectFail   bool
		listObjectsFail  bool
		isBucketOnly     bool
		contextCancelled bool
		fileStructure    map[string]mockFileEntry
		callbackBehavior map[string]error
	}
	type args struct {
		root string
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
		wantErr       bool
		wantCallCount int
	}{
		{
			name: "successful walk with files and directories",
			fields: fields{
				fileStructure: map[string]mockFileEntry{
					"path": {
						IsDir: true,
						Children: map[string]mockFileEntry{
							"file1.txt": {
								Size:    1024,
								ModTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
							},
							"subdir/": {
								IsDir: true,
								Children: map[string]mockFileEntry{
									"file2.txt": {
										Size:    512,
										ModTime: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
									},
								},
							},
						},
					},
				},
			},
			args: args{
				root: "bucket/path",
			},
			wantErr:       false,
			wantCallCount: 4,
		},
		{
			name: "successful walk bucket only",
			fields: fields{
				isBucketOnly: true,
				fileStructure: map[string]mockFileEntry{
					"": { // bucket root
						IsDir: true,
						Children: map[string]mockFileEntry{
							"file1.txt": {
								Size:    1024,
								ModTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
							},
						},
					},
				},
			},
			args: args{
				root: "bucket",
			},
			wantErr:       false,
			wantCallCount: 2,
		},
		{
			name: "callback returns SkipDir on subdirectory",
			fields: fields{
				fileStructure: map[string]mockFileEntry{
					"path": {
						IsDir: true,
						Children: map[string]mockFileEntry{
							"file1.txt": {
								Size:    1024,
								ModTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
							},
							"subdir/": {
								IsDir: true,
								Children: map[string]mockFileEntry{
									"file2.txt": {
										Size:    512,
										ModTime: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
									},
								},
							},
						},
					},
				},
				callbackBehavior: map[string]error{
					"bucket/path/subdir/": fs.SkipDir,
				},
			},
			args: args{
				root: "bucket/path",
			},
			wantErr:       false,
			wantCallCount: 3,
		},
		{
			name: "callback returns SkipAll on first file",
			fields: fields{
				fileStructure: map[string]mockFileEntry{
					"path": {
						IsDir: true,
						Children: map[string]mockFileEntry{
							"file1.txt": {
								Size:    1024,
								ModTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
							},
							"file2.txt": {
								Size:    1024,
								ModTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
							},
						},
					},
				},
				callbackBehavior: map[string]error{
					"bucket/path/file1.txt": fs.SkipAll,
				},
			},
			args: args{
				root: "bucket/path",
			},
			wantErr:       false,
			wantCallCount: 2,
		},
		{
			name: "callback returns custom error",
			fields: fields{
				fileStructure: map[string]mockFileEntry{
					"path": {
						IsDir: true,
						Children: map[string]mockFileEntry{
							"file1.txt": {
								Size:    1024,
								ModTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
							},
						},
					},
				},
				callbackBehavior: map[string]error{
					"bucket/path/file1.txt": errors.New("callback error"),
				},
			},
			args: args{
				root: "bucket/path",
			},
			wantErr:       true,
			wantCallCount: 2,
		},
		{
			name:   "error invalid path",
			fields: fields{},
			args: args{
				root: "",
			},
			wantErr:       true,
			wantCallCount: 0,
		},
		{
			name: "error HeadBucket fails for bucket",
			fields: fields{
				isBucketOnly:   true,
				headBucketFail: true,
			},
			args: args{
				root: "bucket",
			},
			wantCallCount: 1,
		},
		{
			name: "error HeadObject fails (directory case)",
			fields: fields{
				headObjectFail: true,
				fileStructure: map[string]mockFileEntry{
					"path": {
						IsDir: true,
						Children: map[string]mockFileEntry{
							"file1.txt": {
								Size:    1024,
								ModTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
							},
						},
					},
				},
			},
			args: args{
				root: "bucket/path",
			},
			wantErr:       false,
			wantCallCount: 2,
		},
		{
			name: "root is file not directory",
			fields: fields{
				fileStructure: map[string]mockFileEntry{
					"file.txt": {
						Size:    1024,
						ModTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
			args: args{
				root: "bucket/file.txt",
			},
			wantErr:       false,
			wantCallCount: 1,
		},
		{
			name: "error ListObjectsV2 fails",
			fields: fields{
				isBucketOnly:    true,
				listObjectsFail: true,
			},
			args: args{
				root: "bucket",
			},
			wantErr:       true,
			wantCallCount: 1,
		},
		{
			name: "context cancelled",
			fields: fields{
				isBucketOnly:     true,
				contextCancelled: true,
			},
			args: args{
				root: "bucket",
			},
			wantErr:       true,
			wantCallCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			if tt.fields.contextCancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel() // immediately cancel
			}

			callCount := 0
			walkFunc := func(path string, d fs.DirEntry, err error) error {
				callCount++

				// Check if we have a specific behavior for this path
				if behavior, exists := tt.fields.callbackBehavior[path]; exists {
					return behavior
				}
				return nil
			}

			client := &S3ClientMock{
				HeadBucketMock: func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
					if tt.fields.headBucketFail {
						return nil, errors.New("head bucket failed")
					}
					return &s3.HeadBucketOutput{}, nil
				},
				HeadObjectMock: func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
					if tt.fields.headObjectFail || tt.fields.isBucketOnly {
						return nil, errors.New("not found")
					}

					// Extract key from params
					key := ""
					if params.Key != nil {
						key = *params.Key
					}

					// Look for file in mockStructure
					if entry, exists := tt.fields.fileStructure[key]; exists && !entry.IsDir {
						return &s3.HeadObjectOutput{
							ContentLength: aws.Int64(entry.Size),
							LastModified:  &entry.ModTime,
						}, nil
					}

					return nil, errors.New("not found")
				},
				ListObjectsV2Mock: func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
					if tt.fields.contextCancelled && ctx.Err() != nil {
						return nil, ctx.Err()
					}
					if tt.fields.listObjectsFail {
						return nil, errors.New("list failed")
					}

					// Get prefix from params
					prefix := ""
					if params.Prefix != nil {
						prefix = *params.Prefix
					}

					// Find the corresponding entry in mockStructure
					var currentEntry mockFileEntry
					var found bool

					// Navigate through mockStructure based on prefix
					// Try to find exact match first
					if entry, exists := tt.fields.fileStructure[prefix]; exists {
						currentEntry = entry
						found = true
					} else {
						// Try to navigate through the structure
						parts := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
						if len(parts) >= 1 {
							// Look for the base path
							basePath := parts[0]
							if baseEntry, exists := tt.fields.fileStructure[basePath]; exists && baseEntry.IsDir {
								current := baseEntry
								found = true

								// Navigate through remaining parts
								for i := 1; i < len(parts) && found; i++ {
									childKey := parts[i] + "/"
									if childEntry, exists := current.Children[childKey]; exists {
										current = childEntry
									} else {
										found = false
									}
								}

								if found {
									currentEntry = current
								}
							}
						}
					}

					if !found {
						return &s3.ListObjectsV2Output{}, nil
					}

					var contents []types.Object
					var commonPrefixes []types.CommonPrefix

					// Process children
					for childName, childEntry := range currentEntry.Children {
						fullKey := prefix + "/" + childName
						if childEntry.IsDir {
							commonPrefixes = append(commonPrefixes, types.CommonPrefix{
								Prefix: aws.String(fullKey),
							})
						} else {
							contents = append(contents, types.Object{
								Key:          aws.String(fullKey),
								Size:         aws.Int64(childEntry.Size),
								LastModified: &childEntry.ModTime,
								ETag:         aws.String("\"etag\""),
							})
						}
					}

					slices.SortStableFunc(contents, func(a types.Object, b types.Object) int {
						switch {
						case *a.Key < *b.Key:
							return -1
						case *a.Key > *b.Key:
							return 1
						default:
							return 0
						}
					})

					return &s3.ListObjectsV2Output{
						Contents:       contents,
						CommonPrefixes: commonPrefixes,
					}, nil
				},
			}

			s := &S3FileSystem{
				client: client,
				config: S3Config{},
			}

			err := s.WalkDir(ctx, tt.args.root, walkFunc)
			if (err != nil) != tt.wantErr {
				t.Errorf("S3FileSystem.WalkDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if callCount != tt.wantCallCount {
				t.Errorf("S3FileSystem.WalkDir() callCount = %v, wantCallCount %v", callCount, tt.wantCallCount)
			}
		})
	}
}

// StatefulS3ClientMock - Version simplifiée et déterministe
type StatefulS3ClientMock struct {
	*S3ClientMock
	mu           sync.RWMutex
	objects      []types.Object // Slice au lieu de map pour ordre déterministe
	shouldError  bool
	errorMessage string
}

func NewStatefulS3ClientMock() *StatefulS3ClientMock {
	return &StatefulS3ClientMock{
		S3ClientMock: &S3ClientMock{},
		objects:      make([]types.Object, 0),
	}
}

func (m *StatefulS3ClientMock) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

func (m *StatefulS3ClientMock) AddObject(key string, obj types.Object) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove existing object with same key if exists
	for i, existing := range m.objects {
		if *existing.Key == key {
			m.objects[i] = obj
			return
		}
	}

	// Add new object, keeping slice sorted by key for deterministic results
	m.objects = append(m.objects, obj)
}

func (m *StatefulS3ClientMock) RemoveObject(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, obj := range m.objects {
		if *obj.Key == key {
			m.objects = append(m.objects[:i], m.objects[i+1:]...)
			return
		}
	}
}

func (m *StatefulS3ClientMock) SetError(shouldError bool, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldError = shouldError
	m.errorMessage = message
}

func (m *StatefulS3ClientMock) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldError {
		return nil, errors.New(m.errorMessage)
	}

	prefix := ""
	if params.Prefix != nil {
		prefix = *params.Prefix
	}

	// Filter objects by prefix - objects are already sorted
	var contents []types.Object
	for _, obj := range m.objects {
		if strings.HasPrefix(*obj.Key, prefix) {
			// Skip directory markers
			if !strings.HasSuffix(*obj.Key, "/") {
				contents = append(contents, obj)
			}
		}
	}

	// Simple result - pas de pagination pour les tests
	return &s3.ListObjectsV2Output{
		Contents: contents,
	}, nil
}

// Helper pour créer facilement des objets de test
func CreateTestObject(key string, size int64, modTime time.Time) types.Object {
	return types.Object{
		Key:          aws.String(key),
		Size:         aws.Int64(size),
		LastModified: &modTime,
		ETag:         aws.String(fmt.Sprintf("\"etag-%s\"", key)), // ETag unique basé sur la clé
	}
}

func TestS3FileSystem_Watch(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "error nonexistent bucket",
			test: func(t *testing.T) {
				client := &S3ClientMock{
					HeadObjectMock: func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
						return nil, &types.NoSuchBucket{}
					},
					ListObjectsV2Mock: func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
						return nil, &types.NoSuchBucket{}
					},
				}

				fs := &S3FileSystem{
					client: client,
					config: S3Config{},
				}

				_, err := fs.Watch(t.Context(), "nonexistent-bucket/path")
				if err == nil {
					t.Error("expected error when watching nonexistent bucket")
				}
				if !strings.Contains(err.Error(), "NoSuchBucket") {
					t.Errorf("expected error to contain 'NoSuchBucket', got %v", err)
				}
			},
		},
		{
			name: "ok object creation",
			test: func(t *testing.T) {
				mock := NewStatefulS3ClientMock()

				fs := &S3FileSystem{
					client: mock,
					config: S3Config{
						MonitoringPeriod: time.Millisecond,
					},
				}

				watcher, err := fs.Watch(t.Context(), "test-bucket")
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				// Add a new object to simulate creation
				testKey := "prefix/test_create.txt"
				testObject := types.Object{
					Key:          aws.String(testKey),
					Size:         aws.Int64(100),
					LastModified: aws.Time(time.Now()),
					ETag:         aws.String("\"etag1\""),
				}
				mock.AddObject(testKey, testObject)

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  "test-bucket/" + testKey,
					},
				}

				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Second); e != nil {
					t.Error(e)
				}
			},
		},
		{
			name: "ok object modification",
			test: func(t *testing.T) {
				mock := NewStatefulS3ClientMock()

				testKey := "prefix/test_modify.txt"
				originalTime := time.Now().Add(-time.Hour)
				originalObject := types.Object{
					Key:          aws.String(testKey),
					Size:         aws.Int64(100),
					LastModified: &originalTime,
					ETag:         aws.String("\"etag1\""),
				}
				mock.AddObject(testKey, originalObject)

				fs := &S3FileSystem{
					client: mock,
					config: S3Config{
						MonitoringPeriod: time.Millisecond,
					},
				}

				watcher, err := fs.Watch(t.Context(), "test-bucket")
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				// Wait for initial scan to complete
				time.Sleep(time.Millisecond * 10)

				// Modify the object (update timestamp and etag)
				modifiedTime := time.Now()
				modifiedObject := types.Object{
					Key:          aws.String(testKey),
					Size:         aws.Int64(150), // Different size
					LastModified: &modifiedTime,
					ETag:         aws.String("\"etag2\""), // Different etag
				}
				mock.AddObject(testKey, modifiedObject)

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventWrite,
						filename:  "test-bucket/" + testKey,
					},
				}

				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Second); e != nil {
					t.Error(e)
				}
			},
		},
		{
			name: "ok multiple objects",
			test: func(t *testing.T) {
				mock := NewStatefulS3ClientMock()

				fs := &S3FileSystem{
					client: mock,
					config: S3Config{
						MonitoringPeriod: time.Millisecond,
					},
				}

				watcher, err := fs.Watch(t.Context(), "test-bucket")
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				testKey1 := "prefix/file1.txt"
				now := time.Now()
				testObject1 := types.Object{
					Key:          aws.String(testKey1),
					Size:         aws.Int64(100),
					LastModified: &now,
					ETag:         aws.String("\"etag1\""),
				}
				mock.AddObject(testKey1, testObject1)

				testKey2 := "prefix/file2.txt"
				testObject2 := types.Object{
					Key:          aws.String(testKey2),
					Size:         aws.Int64(200),
					LastModified: &now,
					ETag:         aws.String("\"etag2\""),
				}
				mock.AddObject(testKey2, testObject2)

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  "test-bucket/" + testKey1,
					},
					{
						eventType: WatchEventCreate,
						filename:  "test-bucket/" + testKey2,
					},
				}

				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Second); e != nil {
					t.Error(e)
				}
			},
		},
		{
			name: "watch with nested prefix",
			test: func(t *testing.T) {
				mock := NewStatefulS3ClientMock()

				fs := &S3FileSystem{
					client: mock,
					config: S3Config{
						MonitoringPeriod: time.Millisecond,
					},
				}

				watcher, err := fs.Watch(t.Context(), "test-bucket")
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				// Add objects in the nested prefix
				testKey1 := "folder/subfolder/deep_file1.txt"
				testKey2 := "folder/subfolder/deep_file2.txt"

				now := time.Now()
				testObject1 := types.Object{
					Key:          aws.String(testKey1),
					Size:         aws.Int64(100),
					LastModified: &now,
					ETag:         aws.String("\"etag1\""),
				}
				testObject2 := types.Object{
					Key:          aws.String(testKey2),
					Size:         aws.Int64(200),
					LastModified: &now,
					ETag:         aws.String("\"etag2\""),
				}

				mock.AddObject(testKey1, testObject1)
				mock.AddObject(testKey2, testObject2)

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  "test-bucket/" + testKey1,
					},
					{
						eventType: WatchEventCreate,
						filename:  "test-bucket/" + testKey2,
					},
				}

				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Second); e != nil {
					t.Error(e)
				}
			},
		},
		{
			name: "watch bucket root",
			test: func(t *testing.T) {
				mock := NewStatefulS3ClientMock()

				fs := &S3FileSystem{
					client: mock,
					config: S3Config{
						MonitoringPeriod: time.Millisecond,
					},
				}

				watcher, err := fs.Watch(t.Context(), "test-bucket")
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				// Add objects at bucket root
				testKey := "root_file.txt"
				now := time.Now()
				testObject := types.Object{
					Key:          aws.String(testKey),
					Size:         aws.Int64(100),
					LastModified: &now,
					ETag:         aws.String("\"etag1\""),
				}

				mock.AddObject(testKey, testObject)

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  "test-bucket/" + testKey,
					},
				}

				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Second); e != nil {
					t.Error(e)
				}
			},
		},
		{
			name: "error during polling",
			test: func(t *testing.T) {
				mock := NewStatefulS3ClientMock()

				fs := &S3FileSystem{
					client: mock,
					config: S3Config{
						MonitoringPeriod: time.Millisecond,
					},
				}

				watcher, err := fs.Watch(t.Context(), "test-bucket")
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				// Wait for initial scan, then inject error
				time.Sleep(time.Millisecond * 10)
				mock.SetError(true, "polling error")

				// Wait for error to be reported
				ctx, cancel := context.WithTimeout(t.Context(), time.Second*35)
				defer cancel()

				select {
				case err := <-watcher.Errors():
					if !strings.Contains(err.Error(), "polling error") {
						t.Errorf("expected polling error, got: %v", err)
					}
				case <-ctx.Done():
					t.Error("expected error to be reported")
				}
			},
		},
		{
			name: "context cancellation",
			test: func(t *testing.T) {
				mock := NewStatefulS3ClientMock()

				fs := &S3FileSystem{
					client: mock,
					config: S3Config{
						MonitoringPeriod: time.Millisecond,
					},
				}

				ctx, cancel := context.WithCancel(t.Context())

				watcher, err := fs.Watch(ctx, "test-bucket")
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}

				// Cancel context immediately
				cancel()

				// Wait for watcher to stop
				time.Sleep(time.Millisecond * 100)

				if e := watcher.Close(); e != nil {
					t.Errorf("failed to close watcher: %v", e)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}
