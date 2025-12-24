package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ANSI Colors
const (
	ColorRed   = "\033[31m"
	ColorGrey  = "\033[90m"
	ColorReset = "\033[0m"
)

// Custom Flag for multiple wordlists
type wordlistFlag map[string]string

func (w *wordlistFlag) String() string {
	var s []string
	for marker, path := range *w {
		s = append(s, fmt.Sprintf("%s:%s", path, marker))
	}
	return strings.Join(s, ", ")
}

func (w *wordlistFlag) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 2 {
		(*w)[parts[1]] = parts[0]
	} else {
		// Default to WL1 if no marker provided, for backward compatibility
		(*w)["WL1"] = value
	}
	return nil
}

func printBanner() {
	// Top half Red, Bottom half Grey
	fmt.Println(ColorRed + `
  _____      _   _     __ _           _           
 |  __ \    | | | |   / _(_)         | |          
 | |__) |_ _| |_| |__| |_ _ _ __   __| | ___ _ __ ` + ColorReset)
	fmt.Println(ColorGrey + ` |  ___/ _` + "`" + ` | __| '_ \  _| | '_ \ / _` + "`" + ` |/ _ \ '__|
 | |  | (_| | |_| | | | | | | | | | (_| |  __/ |   
 |_|   \__,_|\__|_| |_|_| |_|_| |_|\__,_|\___|_|   
` + ColorReset)
}

func main() {
	printBanner()

	if len(os.Args) < 2 {
		fmt.Println("Usage: pathfinder <action> [flags]")
		fmt.Println("Actions: sub (Subdomain Enumeration), dir (Directory Enumeration)")
		os.Exit(1)
	}

	action := os.Args[1]

	// Define FlagSets
	subCmd := flag.NewFlagSet("sub", flag.ExitOnError)
	dirCmd := flag.NewFlagSet("dir", flag.ExitOnError)

	// Common flags data holders
	var urlTarget, outputFile string
	var rateLimit, threads int
	var verbose bool
	
	// Custom Wordlist Maps
	subWordlists := make(wordlistFlag)
	dirWordlists := make(wordlistFlag)

	// Dir specific flags
	var extensionsFlag string
	var matchCodesFlag string
	var filterSizeFlag string
	var filterCodesFlag string

	// Helper to set up flags
	setupCommonFlags := func(f *flag.FlagSet) {
		f.IntVar(&threads, "t", 50, "Number of concurrent threads")
		f.IntVar(&rateLimit, "rl", 10, "Rate limit (requests per second)")
		f.BoolVar(&verbose, "v", false, "Enable verbose output")
		f.StringVar(&outputFile, "o", "", "Output file to save results")
	}

	// Subdomain Flags
	subCmd.StringVar(&urlTarget, "u", "", "Target URL/Domain with markers (e.g. https://WL1.example.com)")
	subCmd.Var(&subWordlists, "w", "Path to wordlist file (format: /path:MARKER or just /path for WL1)")
	setupCommonFlags(subCmd)

	// Directory Flags
	dirCmd.StringVar(&urlTarget, "u", "", "Target URL with markers (e.g. https://example.com/WL1)")
	dirCmd.Var(&dirWordlists, "w", "Path to wordlist file")
	setupCommonFlags(dirCmd)
	
	dirCmd.StringVar(&extensionsFlag, "f", "", "File extensions to search (comma-separated, e.g., 'php,html')")
	dirCmd.StringVar(&matchCodesFlag, "mc", "200,204,301,302,307,401,403", "Match status codes (comma-separated)")
	dirCmd.StringVar(&filterSizeFlag, "fs", "", "Filter response sizes (comma-separated)")
	dirCmd.StringVar(&filterCodesFlag, "fc", "", "Filter status codes (comma-separated)")

	switch action {
	case "sub":
		subCmd.Parse(os.Args[2:])
		if urlTarget == "" || len(subWordlists) == 0 {
			subCmd.Usage()
			os.Exit(1)
		}
		runSubdomainEnum(urlTarget, subWordlists, threads, rateLimit, verbose, outputFile)
	case "dir":
		dirCmd.Parse(os.Args[2:])
		if urlTarget == "" || len(dirWordlists) == 0 {
			dirCmd.Usage()
			os.Exit(1)
		}
		runDirectoryEnum(urlTarget, dirWordlists, threads, rateLimit, verbose, outputFile, extensionsFlag, matchCodesFlag, filterSizeFlag, filterCodesFlag)
	default:
		fmt.Printf("Unknown action: %s\n", action)
		fmt.Println("Available actions: sub, dir")
		os.Exit(1)
	}
}

// Data loading
func loadWordlists(wMap wordlistFlag) (map[string][]string, error) {
	data := make(map[string][]string)
	for marker, path := range wMap {
		lines, err := readLines(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read wordlist for marker %s at %s: %v", marker, path, err)
		}
		data[marker] = lines
	}
	return data, nil
}

// Recursively generate targets
func generateTargets(template string, markers map[string][]string) []string {
	var foundMarker string
	for marker := range markers {
		if strings.Contains(template, marker) {
			foundMarker = marker
			break
		}
	}

	if foundMarker == "" {
		return []string{template}
	}

	var results []string
	words := markers[foundMarker]
	
	for _, word := range words {
		newTemplate := strings.ReplaceAll(template, foundMarker, word)
		subResults := generateTargets(newTemplate, markers)
		results = append(results, subResults...)
	}

	return results
}

func printConfig(target string, wMap wordlistFlag, threads, rateLimit int, extensions, matchCodes, filterSizes, filterCodes []string) {
	fmt.Printf("[*] Target URL:      %s\n", target)
	fmt.Printf("[*] Threads:         %d\n", threads)
	fmt.Printf("[*] Rate Limit:      %d req/s\n", rateLimit)
	
	fmt.Print("[*] Wordlists:\n")
	for marker, path := range wMap {
		fmt.Printf("    - %s: %s\n", marker, path)
	}

	if len(extensions) > 0 {
		fmt.Printf("[*] Extensions:      %s\n", strings.Join(extensions, ", "))
	}
	if len(matchCodes) > 0 {
		fmt.Printf("[*] Match Codes:     %s\n", strings.Join(matchCodes, ", "))
	}
	if len(filterCodes) > 0 {
		fmt.Printf("[*] Filter Codes:    %s\n", strings.Join(filterCodes, ", "))
	}
	if len(filterSizes) > 0 {
		fmt.Printf("[*] Filter Sizes:    %s\n", strings.Join(filterSizes, ", "))
	}
	
	fmt.Println("------------------------------------------------------------")
}

func runSubdomainEnum(target string, wMap wordlistFlag, threads, rateLimit int, verbose bool, output string) {
	printConfig(target, wMap, threads, rateLimit, nil, nil, nil, nil)

	wordlistData, err := loadWordlists(wMap)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		os.Exit(1)
	}

	// Check markers
	hasMarkers := false
	for marker := range wordlistData {
		if strings.Contains(target, marker) {
			hasMarkers = true
			break
		}
	}

	var targets []string
	if hasMarkers {
		targets = generateTargets(target, wordlistData)
	} else {
		// Compatibility
		if lines, ok := wordlistData["WL1"]; ok {
			cleanTarget := strings.TrimPrefix(target, "http://")
			cleanTarget = strings.TrimPrefix(cleanTarget, "https://")
			cleanTarget = strings.TrimPrefix(cleanTarget, "www.")
			for _, sub := range lines {
				targets = append(targets, fmt.Sprintf("%s.%s", sub, cleanTarget))
			}
		} else {
			fmt.Println("[-] No markers found in URL and no 'WL1' wordlist provided.")
			os.Exit(1)
		}
	}

	file := openOutputFile(output)
	defer closeOutputFile(file)

	// Worker Pool
	jobs := make(chan string, threads)
	var wg sync.WaitGroup

	// Start Workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fullDomain := range jobs {
				// Clean for DNS
				dnsDomain := strings.TrimPrefix(fullDomain, "http://")
				dnsDomain = strings.TrimPrefix(dnsDomain, "https://")

				if verbose {
					fmt.Printf("[DEBUG] Now Scanning: %s\n", fullDomain)
				}

				ips, err := net.LookupHost(dnsDomain)
				if err == nil && len(ips) > 0 {
					msg := fmt.Sprintf("[+] Found: %s -> %v\n", fullDomain, ips)
					fmt.Print(msg)
					writeToFile(file, msg)
				}
			}
		}()
	}

	// Feed Jobs with Rate Limit
	ticker := time.NewTicker(time.Second / time.Duration(rateLimit))
	defer ticker.Stop()

	fmt.Printf("[*] Generated %d targets. Starting scan...\n\n", len(targets))

	for _, t := range targets {
		<-ticker.C
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	fmt.Println("\n[*] Scan Complete.")
}

func runDirectoryEnum(targetURL string, wMap wordlistFlag, threads, rateLimit int, verbose bool, output string, extsStr string, mcStr string, fsStr string, fcStr string) {
	// Parse options strings to slices for display/logic
	extensions := parseStringList(extsStr)
	matchCodesStr := parseStringList(mcStr)
	filterSizesStr := parseStringList(fsStr)
	filterCodesStr := parseStringList(fcStr)

	printConfig(targetURL, wMap, threads, rateLimit, extensions, matchCodesStr, filterSizesStr, filterCodesStr)

	// Parse to ints for logic
	matchCodes := parseIntList(mcStr)
	filterSizes := parseIntList(fsStr)
	filterCodes := parseIntList(fcStr)

	wordlistData, err := loadWordlists(wMap)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		os.Exit(1)
	}

	hasMarkers := false
	for marker := range wordlistData {
		if strings.Contains(targetURL, marker) {
			hasMarkers = true
			break
		}
	}

	var baseTargets []string
	if hasMarkers {
		baseTargets = generateTargets(targetURL, wordlistData)
	} else {
		if !strings.HasPrefix(targetURL, "http") {
			targetURL = "http://" + targetURL
		}
		targetURL = strings.TrimSuffix(targetURL, "/")
		
		if lines, ok := wordlistData["WL1"]; ok {
			for _, word := range lines {
				baseTargets = append(baseTargets, fmt.Sprintf("%s/%s", targetURL, word))
			}
		} else {
			fmt.Println("[-] No markers found in URL and no 'WL1' wordlist provided.")
			os.Exit(1)
		}
	}

	var finalTargets []string
	if len(extensions) > 0 {
		for _, tgt := range baseTargets {
			for _, ext := range extensions {
				ext = strings.TrimPrefix(ext, ".")
				finalTargets = append(finalTargets, fmt.Sprintf("%s.%s", tgt, ext))
			}
		}
	} else {
		finalTargets = baseTargets
	}
	
	file := openOutputFile(output)
	defer closeOutputFile(file)

	// Worker Pool
	jobs := make(chan string, threads)
	var wg sync.WaitGroup

	// Shared Transport for efficiency
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        threads,
		MaxIdleConnsPerHost: threads,
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	// Start Workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fullURL := range jobs {
				// Ensure protocol
				if !strings.HasPrefix(fullURL, "http") {
					fullURL = "http://" + fullURL
				}

				if verbose {
					fmt.Printf("[DEBUG] Now Scanning: %s\r", fullURL)
				}

				resp, err := client.Get(fullURL)
				if err != nil {
					continue
				}
				
				code := resp.StatusCode
				size := resp.ContentLength
				resp.Body.Close()

				if !containsInt(matchCodes, code) { continue }
				if len(filterCodes) > 0 && containsInt(filterCodes, code) { continue }
				if len(filterSizes) > 0 && containsInt64(filterSizes, size) { continue }

				msg := fmt.Sprintf("[+] Found: %s [Code: %d, Size: %d]\n", fullURL, code, size)
				fmt.Print(msg)
				writeToFile(file, msg)
			}
		}()
	}

	// Feed Jobs
	ticker := time.NewTicker(time.Second / time.Duration(rateLimit))
	defer ticker.Stop()

	fmt.Printf("[*] Generated %d requests. Starting scan...\n\n", len(finalTargets))

	for _, req := range finalTargets {
		<-ticker.C
		jobs <- req
	}
	close(jobs)
	wg.Wait()
	fmt.Println("\n[*] Scan Complete.")
}

// Utils

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			lines = append(lines, text)
		}
	}
	return lines, scanner.Err()
}

func openOutputFile(path string) *os.File {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("[-] Error opening output file: %v\n", err)
		return nil
	}
	return f
}

func closeOutputFile(f *os.File) {
	if f != nil {
		f.Close()
	}
}

func writeToFile(f *os.File, msg string) {
	if f != nil {
		f.WriteString(msg)
	}
}

func parseStringList(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseIntList(s string) []int {
	if s == "" {
		return []int{}
	}
	parts := strings.Split(s, ",")
	var result []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if i, err := strconv.Atoi(p); err == nil {
			result = append(result, i)
		}
	}
	return result
}

func containsInt(list []int, item int) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func containsInt64(list []int, item int64) bool {
	for _, v := range list {
		if int64(v) == item {
			return true
		}
	}
	return false
}