package scanner_test

import (
	"fmt"

	"github.com/glimps-re/host-connector/pkg/scanner"
)

func ExampleNewPathFilter() {
	_, err := scanner.NewPathFilter([]string{`\.exe$`}, []string{`^/srv/in/trusted/`})
	fmt.Println(err)

	_, err = scanner.NewPathFilter([]string{`a{101}`}, nil)
	fmt.Println(err != nil)
	// Output:
	// <nil>
	// true
}

func ExamplePathFilter_Apply() {
	filter, err := scanner.NewPathFilter([]string{`\.exe$`}, []string{`^/srv/in/trusted/`})
	if err != nil {
		fmt.Println(err)
		return
	}
	// The logical path of a member of an archive is the path of the archive followed
	// by the path of the member; the second path is the same as the file system gives it.
	res := filter.Apply("/srv/in/trusted/a.zip/run.exe", "/srv/in/trusted/a.zip/run.exe", "/nonexistent", "sha")
	fmt.Println(res.Malware, res.MalwareReason)
	fmt.Println(filter.Apply("/srv/in/other/a.txt", "/srv/in/other/a.txt", "/nonexistent", "sha") == nil)
	// Output:
	// true filtered-filepath
	// true
}
