package filesystem

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/logging"
)

// S3Client abstracts the S3 client methods we use
type S3Client interface {
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error)
	CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error)
}

const (
	DefaultStreamThreshold = 10 * 1024 * 1024 // 10MB
	S3MaxKeys              = 1000
)

// S3Config holds the configuration for S3/Minio client
type S3Config struct {
	Endpoint         string
	Region           string
	AccessKeyID      string
	SecretAccessKey  string
	Insecure         bool
	UsePathStyle     bool
	StreamThreshold  int
	MonitoringPeriod time.Duration
}

// S3FileSystem implements FileSystem interface for S3/Minio
type S3FileSystem struct {
	client S3Client
	config S3Config
}

// noOpLogger implements logging.Logger and discards all logs
type noOpLogger struct{}

func (noOpLogger) Logf(logging.Classification, string, ...any) {}

// NewS3FileSystem creates a new S3FileSystem instance
func NewS3FileSystem(ctx context.Context, cfg S3Config) (fs *S3FileSystem, err error) {
	if cfg.MonitoringPeriod == 0 {
		cfg.MonitoringPeriod = time.Second * 10
	}

	var opts []func(*config.LoadOptions) error

	// Disable SDK Log
	opts = append(opts, config.WithClientLogMode(0), config.WithLogger(noOpLogger{}))

	opts = append(opts, config.WithRegion(cfg.Region))

	if cfg.Insecure {
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // Configuration choose by user
				},
			},
		}
		opts = append(opts, config.WithHTTPClient(httpClient))
	}

	// Set credentials
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}

	// Load config
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return
	}

	// Create S3 client with custom endpoint if provided
	clientOpts := []func(*s3.Options){
		func(o *s3.Options) {
			o.UsePathStyle = cfg.UsePathStyle
			o.ClientLogMode = 0
			o.Logger = noOpLogger{}
		},
	}

	if cfg.Endpoint != "" {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}

	if cfg.StreamThreshold == 0 {
		cfg.StreamThreshold = DefaultStreamThreshold
	}

	client := s3.NewFromConfig(awsCfg, clientOpts...)

	fs = &S3FileSystem{
		client: client,
		config: cfg,
	}
	return
}

// parsePath splits path into bucket and key
func (s *S3FileSystem) parsePath(path string) (bucket, key string, err error) {
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		err = errors.New("invalid path: bucket name required")
		return
	}
	bucket = parts[0]
	if len(parts) > 1 {
		key = parts[1]
	}
	return
}

// s3FileInfo implements fs.FileInfo for S3 objects
type s3FileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
}

func (fi *s3FileInfo) Name() string       { return fi.name }
func (fi *s3FileInfo) Size() int64        { return fi.size }
func (fi *s3FileInfo) Mode() fs.FileMode  { return fi.mode }
func (fi *s3FileInfo) ModTime() time.Time { return fi.modTime }
func (fi *s3FileInfo) IsDir() bool        { return fi.isDir }
func (fi *s3FileInfo) Sys() any           { return nil }

// readSeekCloser implements io.ReadSeekCloser for S3 objects
type readSeekCloser struct {
	*bytes.Reader
	data []byte
}

func newReadSeekCloser(data []byte) *readSeekCloser {
	return &readSeekCloser{
		Reader: bytes.NewReader(data),
		data:   data,
	}
}

func (r *readSeekCloser) Close() error { return nil }

// streamingReadSeekCloser implements io.ReadSeekCloser for large S3 objects using streaming
type streamingReadSeekCloser struct {
	client S3Client
	bucket string
	key    string
	size   int64
	pos    int64
	mu     sync.Mutex
}

func newStreamingReadSeekCloser(client S3Client, bucket, key string, size int64) *streamingReadSeekCloser {
	return &streamingReadSeekCloser{
		client: client,
		bucket: bucket,
		key:    key,
		size:   size,
		pos:    0,
	}
}

func (r *streamingReadSeekCloser) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.pos >= r.size {
		err = io.EOF
		return
	}

	start := r.pos
	end := r.pos + int64(len(p)) - 1
	if end >= r.size {
		end = r.size - 1
	}

	rangeHeader := fmt.Sprintf("bytes=%d-%d", start, end)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := r.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(r.key),
		Range:  aws.String(rangeHeader),
	})
	if err != nil {
		return
	}
	defer func() {
		if e := result.Body.Close(); e != nil {
			Logger.Error("could not close S3 result body", slog.String("error", e.Error()))
		}
	}()

	n, err = io.ReadFull(result.Body, p[:end-start+1])
	r.pos += int64(n)

	if errors.Is(err, io.ErrUnexpectedEOF) && r.pos == r.size {
		err = nil
	}
	return
}

func (r *streamingReadSeekCloser) Seek(offset int64, whence int) (pos int64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch whence {
	case io.SeekStart:
		pos = offset
	case io.SeekCurrent:
		pos = r.pos + offset
	case io.SeekEnd:
		pos = r.size + offset
	default:
		err = errors.New("invalid whence value")
		return
	}

	if pos < 0 {
		pos = 0
		err = errors.New("negative position")
		return
	}

	r.pos = pos
	return
}

func (r *streamingReadSeekCloser) Close() error {
	// Nothing to close for streaming reader
	return nil
}

// Modified Open method that uses streaming for large files
func (s *S3FileSystem) Open(ctx context.Context, name string) (reader io.ReadSeekCloser, err error) {
	bucket, key, err := s.parsePath(name)
	if err != nil {
		return
	}

	if key == "" {
		err = errors.New("cannot open bucket as file")
		return
	}

	// First, get object metadata to check size
	headResult, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return
	}

	objectSize := *headResult.ContentLength
	threshold := s.config.StreamThreshold
	if threshold <= 0 {
		threshold = DefaultStreamThreshold
	}

	// Use streaming for large files
	if int(objectSize) > threshold {
		reader = newStreamingReadSeekCloser(s.client, bucket, key, objectSize)
		return
	}

	// Load file in memory
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return
	}
	defer func() {
		if e := result.Body.Close(); e != nil {
			Logger.Error("could not close result body", slog.String("error", e.Error()))
		}
	}()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return
	}

	reader = newReadSeekCloser(data)
	return
}

// Stat returns file info
func (s *S3FileSystem) Stat(ctx context.Context, name string) (info fs.FileInfo, err error) {
	bucket, key, err := s.parsePath(name)
	if err != nil {
		return
	}

	// If only bucket name, check if bucket exists
	if key == "" {
		_, err = s.client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: aws.String(bucket),
		})
		respErr := new(awshttp.ResponseError)
		switch {
		case err == nil:
			info = &s3FileInfo{
				name:  bucket,
				isDir: true,
				mode:  fs.ModeDir | 0o755,
			}
			return //nolint:nilerr // We want to return bucket info in this case
		case errors.As(err, &respErr) && respErr.Response.StatusCode == http.StatusNotFound:
			err = errors.Join(fs.ErrNotExist, err)
			return
		default:
			return
		}
	}

	// Check if it's a file
	result, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err == nil {
		info = &s3FileInfo{
			name:    path.Base(key),
			size:    *result.ContentLength,
			modTime: *result.LastModified,
			mode:    0o644,
		}
		return //nolint:nilerr // it does not return error
	}

	// Check if it's a directory by looking for objects with this prefix
	listResult, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(key),
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return
	}

	if len(listResult.Contents) > 0 || len(listResult.CommonPrefixes) > 0 {
		info = &s3FileInfo{
			name:  path.Base(key),
			isDir: true,
			mode:  fs.ModeDir | 0o755,
		}
		return
	}

	err = fs.ErrNotExist
	return
}

// Lstat returns file info (same as Stat for S3)
func (s *S3FileSystem) Lstat(ctx context.Context, name string) (info fs.FileInfo, err error) {
	return s.Stat(ctx, name)
}

// WalkDir walks the file tree rooted at root using a simple recursive approach
func (s *S3FileSystem) WalkDir(ctx context.Context, root string, fn fs.WalkDirFunc) (err error) {
	bucket, prefix, err := s.parsePath(root)
	if err != nil {
		return
	}

	rootInfo, err := s.Stat(ctx, root)
	if err != nil {
		return fn(root, nil, err)
	}

	rootEntry := &s3DirEntry{
		name:    rootInfo.Name(),
		isDir:   rootInfo.IsDir(),
		size:    rootInfo.Size(),
		modTime: rootInfo.ModTime(),
	}

	if err = fn(root, rootEntry, nil); err != nil {
		if errors.Is(err, fs.SkipDir) || errors.Is(err, fs.SkipAll) {
			return nil
		}
		return
	}

	if !rootInfo.IsDir() {
		return
	}

	err = s.walkRecursive(ctx, bucket, prefix, fn)
	if errors.Is(err, fs.SkipDir) || errors.Is(err, fs.SkipAll) {
		return nil
	}
	return
}

func (s *S3FileSystem) walkRecursive(ctx context.Context, bucket, prefix string, fn fs.WalkDirFunc) error {
	// Check for context cancellation
	if ctx.Err() != nil {
		return ctx.Err()
	}

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int32(S3MaxKeys),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		// Iterate over subdirs first
		for _, commonPrefix := range page.CommonPrefixes {
			dirPath := bucket + "/" + *commonPrefix.Prefix

			dirEntry := &s3DirEntry{
				name:  path.Base(*commonPrefix.Prefix),
				isDir: true,
			}

			err := fn(dirPath, dirEntry, nil)
			switch {
			case errors.Is(err, fs.SkipDir):
				continue
			case err != nil:
				return err
			}

			if err := s.walkRecursive(ctx, bucket, *commonPrefix.Prefix, fn); err != nil {
				return err
			}
		}

		// Process files
		for _, obj := range page.Contents {
			// Skip directory markers
			if strings.HasSuffix(*obj.Key, "/") {
				continue
			}

			filePath := bucket + "/" + *obj.Key
			fileEntry := &s3DirEntry{
				name:    path.Base(*obj.Key),
				size:    *obj.Size,
				modTime: *obj.LastModified,
				isDir:   false,
			}
			err := fn(filePath, fileEntry, nil)
			switch {
			case errors.Is(err, fs.SkipDir):
				continue
			case err != nil:
				return err
			}
		}
	}

	return nil
}

// s3DirEntry implements fs.DirEntry
type s3DirEntry struct {
	name    string
	size    int64
	modTime time.Time
	isDir   bool
}

func (e *s3DirEntry) Name() string { return e.name }
func (e *s3DirEntry) IsDir() bool  { return e.isDir }
func (e *s3DirEntry) Type() fs.FileMode {
	if e.isDir {
		return fs.ModeDir
	}
	return 0
}

func (e *s3DirEntry) Info() (fs.FileInfo, error) {
	return &s3FileInfo{
		name:    e.name,
		size:    e.size,
		modTime: e.modTime,
		isDir:   e.isDir,
		mode:    e.Type() | 0o644,
	}, nil
}

// Remove deletes a file or empty directory
func (s *S3FileSystem) Remove(ctx context.Context, path string) (err error) {
	bucket, key, err := s.parsePath(path)
	if err != nil {
		return
	}

	if key == "" {
		// Cannot remove bucket through this interface
		err = errors.New("cannot remove bucket")
		return
	}

	// Try to remove as file first
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	return
}

// s3WriteCloser implements io.WriteCloser for S3 uploads
type s3WriteCloser struct {
	client S3Client
	bucket string
	key    string
	buffer *bytes.Buffer
	ctx    context.Context
}

func (w *s3WriteCloser) Write(p []byte) (n int, err error) {
	return w.buffer.Write(p)
}

func (w *s3WriteCloser) Close() (err error) {
	_, err = w.client.PutObject(w.ctx, &s3.PutObjectInput{
		Bucket: aws.String(w.bucket),
		Key:    aws.String(w.key),
		Body:   bytes.NewReader(w.buffer.Bytes()),
	})
	return
}

// Create creates a new file
func (s *S3FileSystem) Create(ctx context.Context, name string) (writer io.WriteCloser, err error) {
	bucket, key, err := s.parsePath(name)
	if err != nil {
		return
	}

	if key == "" {
		err = errors.New("cannot create file without key")
		return
	}

	writer = &s3WriteCloser{
		client: s.client,
		bucket: bucket,
		key:    key,
		buffer: new(bytes.Buffer),
		ctx:    ctx,
	}
	return
}

// MkdirAll creates a directory path
func (s *S3FileSystem) MkdirAll(ctx context.Context, path string, perm fs.FileMode) (err error) {
	bucket, key, err := s.parsePath(path)
	if err != nil {
		return
	}

	err = s.ensureBucketExists(ctx, bucket)
	if err != nil {
		return
	}

	if key == "" {
		return
	}

	if !strings.HasSuffix(key, "/") {
		key += "/"
	}

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte{}),
	})
	return
}

func (s *S3FileSystem) ensureBucketExists(ctx context.Context, bucket string) (err error) {
	// Check if bucket exists
	_, err = s.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	respErr := new(awshttp.ResponseError)
	awsRespErr := new(types.NoSuchBucket)
	switch {
	case errors.As(err, &respErr) && respErr.Response.StatusCode == http.StatusNotFound, errors.As(err, &awsRespErr):
		// Bucket doesn't exist, create it
		_, err = s.client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			// Handle race condition where bucket was created meanwhile
			var bae *types.BucketAlreadyExists
			var baoby *types.BucketAlreadyOwnedByYou
			if errors.As(err, &bae) || errors.As(err, &baoby) {
				err = nil
				return
			}
			return
		}
		return
	default:
		return
	}
}

// Rename moves a file from oldpath to newpath
func (s *S3FileSystem) Rename(ctx context.Context, oldPath, newPath string) (err error) {
	oldBucket, oldKey, err := s.parsePath(oldPath)
	if err != nil {
		return
	}

	newBucket, newKey, err := s.parsePath(newPath)
	if err != nil {
		return
	}

	if oldKey == "" || newKey == "" {
		err = errors.New("cannot rename buckets")
		return
	}

	// Copy object to new location
	copySource := fmt.Sprintf("%s/%s", oldBucket, oldKey)
	_, err = s.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(newBucket),
		Key:        aws.String(newKey),
		CopySource: aws.String(copySource),
	})
	if err != nil {
		return
	}

	// Delete old object
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(oldBucket),
		Key:    aws.String(oldKey),
	})
	return
}

// IsLocal returns false for S3FileSystem
func (s *S3FileSystem) IsLocal() bool {
	return false
}

// Watch starts watching the specified S3 path for changes using polling
func (s *S3FileSystem) Watch(ctx context.Context, s3Path string) (Watcher, error) {
	return newS3Watcher(ctx, s, s3Path)
}

// s3ObjectInfo represents an S3 object for comparison
type s3ObjectInfo struct {
	key          string
	lastModified time.Time
	size         int64
}

// s3Watcher implements Watcher interface for S3 filesystem using polling
type s3Watcher struct {
	fs           *S3FileSystem
	bucket       string
	prefix       string
	events       chan WatchEvent
	errors       chan error
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.RWMutex
	knownObjects map[string]s3ObjectInfo
	pollInterval time.Duration
}

func newS3Watcher(ctx context.Context, fs *S3FileSystem, s3Path string) (*s3Watcher, error) {
	bucket, prefix, err := fs.parsePath(s3Path)
	if err != nil {
		return nil, err
	}

	_, err = fs.Stat(ctx, s3Path)
	if err != nil {
		return nil, err
	}

	watchCtx, cancel := context.WithCancel(ctx)

	w := &s3Watcher{
		fs:           fs,
		bucket:       bucket,
		prefix:       prefix,
		events:       make(chan WatchEvent, 100),
		errors:       make(chan error, 10),
		done:         make(chan struct{}),
		ctx:          watchCtx,
		cancel:       cancel,
		knownObjects: make(map[string]s3ObjectInfo),
		pollInterval: fs.config.MonitoringPeriod,
	}

	// Initialize with current state
	if err := w.initialScan(); err != nil {
		cancel()
		return nil, err
	}

	// Start polling goroutine
	go w.poll()

	return w, nil
}

func (w *s3Watcher) initialScan() (err error) {
	objects, err := w.listObjects()
	if err != nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	for _, obj := range objects {
		w.knownObjects[obj.key] = obj
	}

	return
}

func (w *s3Watcher) listObjects() ([]s3ObjectInfo, error) {
	var objects []s3ObjectInfo

	paginator := s3.NewListObjectsV2Paginator(w.fs.client, &s3.ListObjectsV2Input{
		Bucket: &w.bucket,
		Prefix: &w.prefix,
	})

	for paginator.HasMorePages() {
		select {
		case <-w.ctx.Done():
			return nil, w.ctx.Err()
		default:
		}

		page, err := paginator.NextPage(w.ctx)
		if err != nil {
			return nil, err
		}

		for _, obj := range page.Contents {
			// Skip directory markers
			if strings.HasSuffix(*obj.Key, "/") {
				continue
			}

			objects = append(objects, s3ObjectInfo{
				key:          *obj.Key,
				lastModified: *obj.LastModified,
				size:         *obj.Size,
			})
		}
	}

	return objects, nil
}

func (w *s3Watcher) poll() {
	defer close(w.done)
	defer close(w.events)
	defer close(w.errors)

	ticker := time.NewTicker(w.pollInterval)

	for {
		select {
		case <-w.ctx.Done():
			return

		case <-ticker.C:
			if err := w.checkForChanges(); err != nil {
				select {
				case w.errors <- err:
				case <-w.ctx.Done():
					return
				}
			}
		}
	}
}

func (w *s3Watcher) checkForChanges() error {
	objects, err := w.listObjects()
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Check for new or modified objects
	for _, o := range objects {
		if known, ok := w.knownObjects[o.key]; ok {
			// Check if object was modified
			if o.lastModified.After(known.lastModified) ||
				o.size != known.size {
				w.sendEvent(WatchEventWrite, o)
			}
			continue
		}
		w.sendEvent(WatchEventCreate, o)
	}

	// Create map of current objects for easy lookup
	objectsByKey := make(map[string]s3ObjectInfo)
	for _, obj := range objects {
		objectsByKey[obj.key] = obj
	}
	w.knownObjects = objectsByKey
	return nil
}

func (w *s3Watcher) sendEvent(eventType WatchEventType, obj s3ObjectInfo) {
	// Create file info for the event
	fileInfo := &s3FileInfo{
		name:    path.Base(obj.key),
		size:    obj.size,
		modTime: obj.lastModified,
		isDir:   false,
		mode:    0o644,
	}

	fullPath := w.bucket + "/" + obj.key

	event := WatchEvent{
		Path:     fullPath,
		Type:     eventType,
		Time:     time.Now(),
		FileInfo: fileInfo,
	}

	select {
	case w.events <- event:
	case <-w.ctx.Done():
		return
	}
}

func (w *s3Watcher) Events() <-chan WatchEvent {
	return w.events
}

func (w *s3Watcher) Errors() <-chan error {
	return w.errors
}

func (w *s3Watcher) Close() error {
	w.cancel()
	<-w.done
	return nil
}
