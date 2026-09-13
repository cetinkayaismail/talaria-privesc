package scanners

import (
	"debug/elf"
	"strings"
	"unicode"
)

// ExecutionSymbols defines libc functions that execute commands by resolving
// through $PATH or invoking a shell (/bin/sh -c).
var ExecutionSymbols = map[string]bool{
	"system":  true,
	"popen":   true,
	"execvp":  true,
	"execlp":  true,
	"execvpe": true,
}

// HijackableCommands defines known command binaries commonly targeted for
// PATH hijacking when executed without absolute directory prefixes.
var HijackableCommands = map[string]bool{
	"chmod": true, "chown": true, "systemctl": true, "service": true,
	"curl": true, "wget": true, "cat": true, "sed": true, "awk": true,
	"tar": true, "cp": true, "mv": true, "rm": true, "id": true,
	"whoami": true, "uname": true, "grep": true, "find": true,
	"netstat": true, "ss": true, "iptables": true, "ip": true,
	"ifconfig": true, "head": true, "tail": true, "cut": true,
	"tee": true, "touch": true, "mkdir": true, "python": true,
	"python3": true, "perl": true, "ruby": true, "bash": true,
	"sh": true, "zsh": true, "nc": true, "ncat": true, "socat": true,
	"rsync": true, "ping": true, "date": true, "hostname": true,
	"ps": true, "kill": true, "gzip": true, "gunzip": true,
}

// DeepELFMatch holds heuristic PATH hijack findings extracted from an ELF binary.
type DeepELFMatch struct {
	Command    string `json:"command"`
	RawString  string `json:"raw_string"`
	ExecSymbol string `json:"exec_symbol"`
}

// HasCommandExecutionSymbols checks if an ELF binary imports command execution
// functions from libc via .dynsym / dynamic symbol tables.
func HasCommandExecutionSymbols(f *elf.File) (bool, string) {
	if symbols, err := f.ImportedSymbols(); err == nil {
		for _, sym := range symbols {
			name := strings.TrimPrefix(sym.Name, "__")
			if ExecutionSymbols[sym.Name] || ExecutionSymbols[name] {
				return true, sym.Name
			}
		}
	}

	if dynSyms, err := f.DynamicSymbols(); err == nil {
		for _, sym := range dynSyms {
			name := strings.TrimPrefix(sym.Name, "__")
			if ExecutionSymbols[sym.Name] || ExecutionSymbols[name] {
				return true, sym.Name
			}
		}
	}

	return false, ""
}

// extractPrintableStrings extracts null-terminated ASCII strings from raw bytes.
func extractPrintableStrings(data []byte, minLen, maxLen int) []string {
	var result []string
	var current []rune

	for _, b := range data {
		if b == 0 {
			if len(current) >= minLen && len(current) <= maxLen {
				result = append(result, string(current))
			}
			current = nil
			continue
		}

		r := rune(b)
		if unicode.IsPrint(r) && r < 128 {
			current = append(current, r)
			if len(current) > maxLen {
				current = nil
			}
		} else {
			current = nil
		}
	}

	if len(current) >= minLen && len(current) <= maxLen {
		result = append(result, string(current))
	}
	return result
}

// ExtractRodataStrings reads the .rodata section and extracts printable strings.
func ExtractRodataStrings(f *elf.File) []string {
	sec := f.Section(".rodata")
	if sec == nil {
		return nil
	}
	// Safety bound: 2MB max read to avoid heavy memory allocation
	if sec.Size > 2*1024*1024 {
		return nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil
	}
	return extractPrintableStrings(data, 2, 256)
}

// isCleanCommandToken verifies that a candidate token is a valid command name
// without shell punctuation, colons, or assignment characters.
func isCleanCommandToken(token string) bool {
	if len(token) == 0 || len(token) > 32 {
		return false
	}
	for _, ch := range token {
		if !unicode.IsLetter(ch) && !unicode.IsDigit(ch) && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}

// AnalyzeDeepELF performs heuristic PATH hijack inspection on an ELF binary:
// 1. Verifies dynamic symbol table imports execution functions (system, popen, execvp, etc.)
// 2. Extracts printable strings from .rodata
// 3. Filters out absolute paths (starting with /)
// 4. Matches against the HijackableCommands allowlist.
func AnalyzeDeepELF(path string) (*DeepELFMatch, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Filter 4: Symbol Table Correlation (.dynsym)
	hasExec, execSym := HasCommandExecutionSymbols(f)
	if !hasExec {
		return nil, nil
	}

	stringsList := ExtractRodataStrings(f)
	if len(stringsList) == 0 {
		return nil, nil
	}

	for _, s := range stringsList {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		// Filter 2: Absolute Path Filter — discard paths starting with '/'
		if strings.HasPrefix(s, "/") {
			continue
		}

		fields := strings.Fields(s)
		if len(fields) == 0 {
			continue
		}
		candidate := strings.ToLower(fields[0])

		// Filter 3: Clean token & Command Name Allowlist
		if isCleanCommandToken(candidate) && HijackableCommands[candidate] {
			return &DeepELFMatch{
				Command:    candidate,
				RawString:  s,
				ExecSymbol: execSym,
			}, nil
		}
	}

	return nil, nil
}
