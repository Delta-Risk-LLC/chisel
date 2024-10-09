package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/blakesmith/ar"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/canonical/chisel/internal/fsutil"
	"github.com/canonical/chisel/internal/strdist"
)

type ExtractOptions struct {
	Package   string
	TargetDir string
	Extract   map[string][]ExtractInfo
	// Create can optionally be set to control the creation of extracted entries.
	// extractInfos is set to the matching entries in Extract, and is nil in cases where
	// the created entry is implicit and unlisted (for example, parent directories).
	Create func(extractInfos []ExtractInfo, options *fsutil.CreateOptions) error
}

type ExtractInfo struct {
	Path     string
	Mode     uint
	Optional bool
	Context  any
}

func getValidOptions(options *ExtractOptions) (*ExtractOptions, error) {
	for extractPath, extractInfos := range options.Extract {
		isGlob := strings.ContainsAny(extractPath, "*?")
		if isGlob {
			for _, extractInfo := range extractInfos {
				if extractInfo.Path != extractPath || extractInfo.Mode != 0 {
					return nil, fmt.Errorf("when using wildcards source and target paths must match: %s", extractPath)
				}
			}
		}
	}

	if options.Create == nil {
		validOpts := *options
		validOpts.Create = func(_ []ExtractInfo, o *fsutil.CreateOptions) error {
			_, err := fsutil.Create(o)
			return err
		}
		return &validOpts, nil
	}

	return options, nil
}

func Extract(pkgReader io.Reader, options *ExtractOptions) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("cannot extract from package %q: %w", options.Package, err)
		}
	}()

	logf("Extracting files from package %q...", options.Package)

	validOpts, err := getValidOptions(options)
	if err != nil {
		return err
	}

	_, err = os.Stat(validOpts.TargetDir)
	if os.IsNotExist(err) {
		return fmt.Errorf("target directory does not exist")
	} else if err != nil {
		return err
	}

	arReader := ar.NewReader(pkgReader)
	var dataReader io.Reader
	for dataReader == nil {
		arHeader, err := arReader.Next()
		if err == io.EOF {
			return fmt.Errorf("no data payload")
		}
		if err != nil {
			return err
		}
		switch arHeader.Name {
		case "data.tar.gz":
			gzipReader, err := gzip.NewReader(arReader)
			if err != nil {
				return err
			}
			defer gzipReader.Close()
			dataReader = gzipReader
		case "data.tar.xz":
			xzReader, err := xz.NewReader(arReader)
			if err != nil {
				return err
			}
			dataReader = xzReader
		case "data.tar.zst":
			zstdReader, err := zstd.NewReader(arReader)
			if err != nil {
				return err
			}
			defer zstdReader.Close()
			dataReader = zstdReader
		}
	}
	return extractData(dataReader, validOpts)
}

func extractData(dataReader io.Reader, options *ExtractOptions) error {

	oldUmask := syscall.Umask(0)
	defer func() {
		syscall.Umask(oldUmask)
	}()

	pendingPaths := make(map[string]bool)
	createdFiles := make(map[string]string) // Track created file paths for hard links

	for extractPath, extractInfos := range options.Extract {
		for _, extractInfo := range extractInfos {
			if !extractInfo.Optional {
				pendingPaths[extractPath] = true
				break
			}
		}
	}

	// When creating a file we will iterate through its parent directories and
	// create them with the permissions defined in the tarball.
	//
	// The assumption is that the tar entries of the parent directories appear
	// before the entry for the file itself. This is the case for .deb files but
	// not for all tarballs.
	tarDirMode := make(map[string]fs.FileMode)
	tarReader := tar.NewReader(dataReader)
	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		logf("Reading entry: %s, type: %d, size: %d", tarHeader.Name, tarHeader.Typeflag, tarHeader.Size)

		sourcePath := tarHeader.Name
		if len(sourcePath) < 3 || sourcePath[0] != '.' || sourcePath[1] != '/' {
			continue
		}
		sourcePath = sourcePath[1:]
		if sourcePath == "" {
			continue
		}

		sourceIsDir := sourcePath[len(sourcePath)-1] == '/'
		if sourceIsDir {
			tarDirMode[sourcePath] = tarHeader.FileInfo().Mode()
		}

		// Find all globs and copies that require this source, and map them by
		// their target paths on disk.
		targetPaths := map[string][]ExtractInfo{}
		for extractPath, extractInfos := range options.Extract {
			if extractPath == "" {
				continue
			}
			if strings.ContainsAny(extractPath, "*?") {
				if strdist.GlobPath(extractPath, sourcePath) {
					targetPaths[sourcePath] = append(targetPaths[sourcePath], extractInfos...)
					delete(pendingPaths, extractPath)
				}
			} else if extractPath == sourcePath {
				for _, extractInfo := range extractInfos {
					targetPaths[extractInfo.Path] = append(targetPaths[extractInfo.Path], extractInfo)
				}
				delete(pendingPaths, extractPath)
			}
		}
		if len(targetPaths) == 0 {
			// Nothing to do.
			continue
		}

		var contentCache []byte
		var contentIsCached = len(targetPaths) > 1 && !sourceIsDir
		if contentIsCached {
			// Read and cache the content so it may be reused.
			// As an alternative, to avoid having an entire file in
			// memory at once this logic might open the first file
			// written and copy it every time. For now, the choice
			// is speed over memory efficiency.
			data, err := io.ReadAll(tarReader)
			if err != nil {
				return err
			}
			if int64(len(data)) != tarHeader.Size {
				logf("Warning: Expected size %d for %s, but got %d", tarHeader.Size, sourcePath, len(data))
			}
			contentCache = data
		}

		var pathReader io.Reader = tarReader
		for targetPath, extractInfos := range targetPaths {
			if contentIsCached {
				logf("Caching content of size %d for %s", len(contentCache), sourcePath)
				pathReader = bytes.NewReader(contentCache)
			}
			mode := extractInfos[0].Mode
			for _, extractInfo := range extractInfos {
				if extractInfo.Mode != mode {
					if mode < extractInfo.Mode {
						mode, extractInfo.Mode = extractInfo.Mode, mode
					}
					return fmt.Errorf("path %s requested twice with diverging mode: 0%03o != 0%03o", targetPath, mode, extractInfo.Mode)
				}
			}
			if mode != 0 {
				tarHeader.Mode = int64(mode)
			}
			// Create the parent directories using the permissions from the tarball.
			parents := parentDirs(targetPath)
			for _, path := range parents {
				if path == "/" {
					continue
				}
				mode, ok := tarDirMode[path]
				if !ok {
					continue
				}
				delete(tarDirMode, path)

				createOptions := &fsutil.CreateOptions{
					Path:        filepath.Join(options.TargetDir, path),
					Mode:        mode,
					MakeParents: true,
				}
				err := options.Create(nil, createOptions)
				if err != nil {
					return err
				}
			}
			
			if tarHeader.Typeflag == tar.TypeLink {
				logf("Handling hardlink for: %s", targetPath)
				
				// Handle hard links
				originalPath := tarHeader.Linkname
				logf("Link name for hard link: %s", originalPath)
			
				// Adjust originalPath to be absolute if necessary
				if !filepath.IsAbs(originalPath) { // Check if the originalPath is not absolute # new
					originalPath = filepath.Join(filepath.Dir(targetPath), originalPath) // Construct the correct path # new
					logf("Adjusted original path to: %s", originalPath) // New logging
				}
			
				createdFilePath, exists := createdFiles[originalPath]
				logf("Created file path for original: %s, exists: %v", createdFilePath, exists)
			
				if exists {
					logf("Original file exists at: %s", createdFilePath)
					// If the original file exists, create a hard link to it
					err := os.Link(createdFilePath, filepath.Join(options.TargetDir, targetPath))
					logf("Creating hard link from %s to %s", createdFilePath, filepath.Join(options.TargetDir, targetPath))
					
					if err != nil {
						logf("Failed to create hard link: %v", err) // New logging
						return fmt.Errorf("failed to create hard link from %s to %s: %w", createdFilePath, targetPath, err)
					}
					logf("Successfully created hard link to: %s", filepath.Join(options.TargetDir, targetPath))
				} else {
					logf("Original file does not exist, will create a new file at: %s", filepath.Join(options.TargetDir, targetPath))
					
					// If the original file does not exist, create the file normally
					createOptions := &fsutil.CreateOptions{
						Path:        filepath.Join(options.TargetDir, targetPath),
						Mode:        tarHeader.FileInfo().Mode(),
						Data:        pathReader,
						MakeParents: true,
					}
					err := options.Create(extractInfos, createOptions)
					if err != nil {
						logf("Failed to create new file: %v", err) // New logging
						return err
					}
					
					// Track the created file
					createdFiles[targetPath] = filepath.Join(options.TargetDir, targetPath)
					logf("Tracked created file: %s", createdFiles[targetPath]) // New logging for created file
				}
			} else {
				logf("Regular file or symlink for: %s", targetPath)
				
				// Regular file or symlink handling
				createOptions := &fsutil.CreateOptions{
					Path:        filepath.Join(options.TargetDir, targetPath),
					Mode:        tarHeader.FileInfo().Mode(),
					Data:        pathReader,
					Link:        tarHeader.Linkname,
					MakeParents: true,
				}
				err := options.Create(extractInfos, createOptions)
				if err != nil {
					logf("Failed to create regular file: %v", err) // New logging
					return err
				}
				
				// Track the created file for potential hard links
				createdFiles[targetPath] = filepath.Join(options.TargetDir, targetPath)
				logf("Tracked created file for potential hard link: %s", createdFiles[targetPath]) // New logging
			}
			
			// Log the final state of created files
			logf("Current state of created files: %+v", createdFiles) // New logging
		}

	}

	if len(pendingPaths) > 0 {
		pendingList := make([]string, 0, len(pendingPaths))
		for pendingPath := range pendingPaths {
			pendingList = append(pendingList, pendingPath)
		}
		if len(pendingList) == 1 {
			return fmt.Errorf("no content at %s", pendingList[0])
		} else {
			sort.Strings(pendingList)
			return fmt.Errorf("no content at:\n- %s", strings.Join(pendingList, "\n- "))
		}
	}

	return nil
}

func parentDirs(path string) []string {
	path = filepath.Clean(path)
	parents := make([]string, strings.Count(path, "/"))
	count := 0
	for i, c := range path {
		if c == '/' {
			parents[count] = path[:i+1]
			count++
		}
	}
	return parents
}
