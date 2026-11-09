package leaks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

// jsString puts a PEM block into a JavaScript string the way bundlers do:
// one line, with escaped line breaks.
func jsString(block string) string {
	return `const key = "` + strings.ReplaceAll(block, "\n", `\n`) + `";`
}

// armor wraps data in a block with the given header name, in lines of 64.
func armor(label string, data []byte, extra ...string) string {
	b64 := base64.StdEncoding.EncodeToString(data)
	var lines []string
	lines = append(lines, "-----BEGIN "+label+"-----")
	lines = append(lines, extra...)
	for len(b64) > 64 {
		lines = append(lines, b64[:64])
		b64 = b64[64:]
	}
	lines = append(lines, b64, "-----END "+label+"-----")
	return strings.Join(lines, "\n") + "\n"
}

func scanComplete(t *testing.T, text string) []Leak {
	t.Helper()
	leaks, err := ScanReader("app.js", strings.NewReader(text), Options{CompleteKeys: true})
	if err != nil {
		t.Fatal(err)
	}
	return leaks
}

func TestCompleteKeys(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPKCS8, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	// A DER structure whose base64 lines end and start with "+", which
	// source code also uses to join strings.
	plus := make([]byte, 260)
	rand.Read(plus)
	plus[0], plus[1], plus[2], plus[3] = 0x30, 0x82, 0x01, 0x00
	plus[47], plus[48] = 0x3e, 0xf8
	openssh := append([]byte("openssh-key-v1\x00"), make([]byte, 300)...)
	rand.Read(openssh[15:])
	pgp := make([]byte, 300)
	rand.Read(pgp)
	pgp[0] = 0x95
	cipher := make([]byte, 160)
	rand.Read(cipher)

	privateKey, rsaKey, ecKey := "PRIVATE "+"KEY", "RSA PRIVATE "+"KEY", "EC PRIVATE "+"KEY"
	plusBlock := armor(rsaKey, plus)
	plusLines := strings.Split(strings.TrimSuffix(plusBlock, "\n"), "\n")
	if !strings.HasSuffix(plusLines[1], "+") || !strings.HasPrefix(plusLines[2], "+") {
		t.Fatalf("the test key has no + at the line ends: %q", plusLines[1:3])
	}
	concatenated := "const key = `" + plusLines[0] + "\n` +\n"
	for _, l := range plusLines[1:] {
		concatenated += `  "` + l + `\n" +` + "\n"
	}
	concatenated += `  "";`

	for name, text := range map[string]string{
		"PKCS #8 in a script":           jsString(armor(privateKey, pkcs8)),
		"SEC 1 on lines of its own":     armor(ecKey, sec1),
		"Ed25519, the smallest key":     jsString(armor(privateKey, edPKCS8)),
		"joined strings with + in data": concatenated,
		"OpenSSH":                       jsString(armor("OPENSSH PRIVATE "+"KEY", openssh)),
		"OpenPGP with its checksum":     armor("PGP PRIVATE KEY "+"BLOCK", pgp, "Version: Test", "", "=ab12"),
		"encrypted PEM":                 armor(rsaKey, cipher, "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0A1B2C3D0A1B2C3D0A1B2C3D0A1B2C3D", ""),
	} {
		if leaks := scanComplete(t, text); len(leaks) != 1 || leaks[0].RuleID != "private-key" {
			t.Errorf("%s: got %+v, want the key", name, leaks)
		}
	}

	whole := armor(privateKey, pkcs8)
	random, _ := pemKey(privateKey, 500)
	for name, text := range map[string]string{
		// The start every 2048-bit RSA key in PKCS #8 shares, as in
		// documentation and placeholders.
		"excerpt":            jsString("-----BEGIN " + privateKey + "-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ...\n-----END " + privateKey + "-----\n"),
		"excerpt, no dots":   jsString("-----BEGIN " + privateKey + "-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END " + privateKey + "-----\n"),
		"cut-off END line":   jsString("-----BEGIN " + privateKey + "-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END"),
		"no END line":        strings.TrimSuffix(whole, "-----END "+privateKey+"-----\n"),
		"another END line":   strings.Replace(whole, "-----END "+privateKey, "-----END "+rsaKey, 1),
		"random data":        random,
		"header in a string": `if (s.startsWith("-----BEGIN ` + privateKey + `-----")) {`,
	} {
		if leaks := scanComplete(t, text); len(leaks) != 0 {
			t.Errorf("%s: got %+v, want none", name, leaks)
		}
	}
	// Without CompleteKeys, the scanner still reports key data without
	// checking its form.
	if leaks, _ := ScanReader("k", strings.NewReader(random), Options{}); len(leaks) != 1 {
		t.Errorf("random key data without CompleteKeys: %+v", leaks)
	}
	if b, _ := pem.Decode([]byte(whole)); b == nil {
		t.Error("the test block is not PEM")
	}
}

// AWS documents an example key pair; it and other values marked as
// examples are not leaks.
func TestAWSExampleKeys(t *testing.T) {
	for _, line := range []string{
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY",
		`var c={secretAccessKey:"wJalrXUtnFEMI/K7MDENG/` + `bPxRfiCYEXAMPLEKEY"}`,
		"aws_secret_access_key = " + fake(alnum, 16, 600) + "EXAMPLE" + fake(alnum, 17, 601),
	} {
		if leaks, _ := ScanReader("x", strings.NewReader(line), Options{}); len(leaks) != 0 {
			t.Errorf("%q: got %+v", line, leaks)
		}
	}
}
