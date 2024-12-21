package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gocolly/colly"
	"golang.org/x/net/publicsuffix"
)

type Progress struct {
	visitedLinks      int64
	matchingFiles     int64
	downloaded        int64
	alreadyDownloaded int64
	failedDownload    int64
	currentURL        string
	lastURLUpdate     time.Time
}

type progressWriter struct {
	total      int64
	written    int64
	writer     io.Writer
	filename   string
	downloaded int64
}

var (
	progress          = &Progress{}
	progressMutex     = &sync.RWMutex{}
	fileWriteMutex    = &sync.RWMutex{}
	visitedLinks      = make(map[string]bool)
	visitedLinksMutex = &sync.RWMutex{}
	downloadClient    = &http.Client{
		Timeout: 10 * time.Minute,
		Transport: &http.Transport{
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: true, // Important for binary files
		},
	}
)

var ErrFileAlreadyDownloaded = errors.New("file already downloaded")

func main() {
	downloadClient = &http.Client{
		Timeout: 30 * time.Minute,
		Transport: &http.Transport{
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: true,
			MaxConnsPerHost:    10,
			DisableKeepAlives:  false,
			ForceAttemptHTTP2:  true,
		},
	}

	showBanner()

	var fileGroups = map[string][]string{
		"images": {
			".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".tiff", ".tif", ".ico", ".webp", ".heic", ".heif", ".avif", ".jif", ".jfif", ".jpx", ".jp2", ".jxr", ".wdp", ".hdp",
			".indd", ".ai", ".psd",
		},
		"movies": {
			".mov", ".avi", ".mp4", ".mkv", ".flv", ".wmv", ".m4v", ".3gp", ".mpg", ".mpeg", ".webm", ".ogv", ".rm", ".rmvb", ".asf", ".divx", ".xvid", ".qt", ".vob",
			".ts", ".mts", ".m2ts",
		},
		"audio": {
			".wav", ".mp3", ".aac", ".flac", ".m4a", ".ogg", ".wma", ".aiff", ".aif", ".ape", ".opus", ".amr", ".awb", ".mid", ".midi",
		},
		"archives": {
			".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".rar", ".7z", ".bz2", ".gz", ".xz", ".jar", ".war", ".ear", ".iso", ".dmg", ".cab", ".msi", ".deb", ".rpm",
			".apk",
		},
		"documents": {
			".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv", ".tsv", ".ps",
			".wpd", ".pages", ".key", ".numbers", ".epub", ".mobi", ".azw", ".azw3",
			".html", ".htm", ".xhtml",
			".tex", ".ltx",
		},
		"configs": {
			".json", ".yaml", ".yml", ".xml", ".ini", ".conf", ".cfg", ".toml", ".properties", ".env", ".htaccess", ".htpasswd",
		},
		"logs": {
			".log", ".out", ".err", ".syslog", ".event", ".trace", ".dump",
		},
		"databases": {
			".db", ".sql", ".dbf", ".mdb", ".accdb", ".sqlite", ".sqlite3", ".csv", ".tsv", ".json", ".psql", ".dump", ".bak",
		},
		"executables": {
			".exe", ".msi", ".bat", ".com", ".sh", ".bin", ".elf", ".apk", ".dmg", ".app",
		},
		"code": {
			".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".java", ".py", ".js", ".php", ".rb", ".go", ".swift", ".kt", ".rs", ".html", ".css", ".scss", ".less", ".xml", ".json", ".yaml", ".yml", ".sql",
		},
		"fonts": {
			".ttf", ".otf", ".woff", ".woff2", ".eot", ".fon",
		},
	}

	urlFlag := flag.String("url", "", "The target URL to search including http:// or https://")
	depthFlag := flag.Int("depth", 10, "The maximum depth to follow links")
	fileTypesFlag := flag.String("filetypes", "documents", "Comma-separated list of file extensions to download")
	userAgentFlag := flag.String("useragent", "random", "The User-Agent string to use")
	fileTextFlag := flag.String("filetext", "", "The text to be present in the filename (optional)")
	downloadExternalFlag := flag.Bool("external", true, "Enable or disable downloading files from external domains")
	timeOutFlag := flag.Int("timeout", 10, "The maximum time in minutes the crawler will run")
	concurrentDownloadsFlag := flag.Int("concurrent", 5, "Maximum number of concurrent downloads")

	flag.Parse()

	if *urlFlag == "" {
		fmt.Println("No target address URL specified.")
		usage()
	}

	fileTypes := make(map[string]bool)
	for _, fileType := range strings.Split(*fileTypesFlag, ",") {
		if group, ok := fileGroups[fileType]; ok {
			for _, ft := range group {
				fileTypes[ft] = true
			}
		} else {
			fileTypes[fileType] = true
		}
	}

	if *userAgentFlag == "random" {
		userAgents := []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
		}

		source := rand.NewSource(time.Now().UnixNano())
		random := rand.New(source)

		*userAgentFlag = userAgents[random.Intn(len(userAgents))]
	}

	checkedURL, ok := checkURL(*urlFlag, *userAgentFlag)
	if !ok {
		fmt.Printf("The target URL is not valid or not reachable.\n")
		return
	}

	parsedURL, err := url.Parse(checkedURL)
	if err != nil {
		fmt.Printf("Failed to parse URL: %v\n", err)
		return
	}

	cleanTargetString := getCleanDomain(parsedURL.Hostname())
	setupLogging(cleanTargetString)

	fmt.Printf("TargetURL:   %s\n", checkedURL)
	fmt.Printf("CrawlDepth:  %d\n", *depthFlag)
	fmt.Printf("UserAgent:   %s\n", *userAgentFlag)
	fmt.Printf("FileType(s): %s\n", *fileTypesFlag)
	fmt.Printf("Directory:   %s\n\n", cleanTargetString)

	// Create download semaphore
	semaphore := make(chan struct{}, *concurrentDownloadsFlag)

	// Setup collector
	c := colly.NewCollector(
		colly.MaxDepth(*depthFlag),
		colly.UserAgent(*userAgentFlag),
		colly.AllowedDomains(parsedURL.Hostname()),
		colly.Async(true),
		colly.CacheDir("./_cache"),
	)

	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: *concurrentDownloadsFlag,
		Delay:       1 * time.Second,
		RandomDelay: 3 * time.Second,
	})

	setupCollectorCallbacks(c, fileTypes, *fileTextFlag, cleanTargetString, *userAgentFlag, *downloadExternalFlag, semaphore)

	// Setup context and signal handling
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeOutFlag)*time.Minute)
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Start crawling
	done := make(chan bool)
	go func() {
		c.Visit(checkedURL)
		c.Wait()
		done <- true
	}()

	select {
	case <-ctx.Done():
		fmt.Println("\n\nTimeout reached, stopping...")
	case <-done:
		fmt.Println("\n\nFinished crawling.")
	case <-sig:
		fmt.Println("\n\nSignal received, stopping...")
	}
}

func setupCollectorCallbacks(c *colly.Collector, fileTypes map[string]bool, fileText, cleanTargetString, userAgent string, downloadExternal bool, semaphore chan struct{}) {
	var isFirstRequest = true

	c.OnRequest(func(r *colly.Request) {
		if !isFirstRequest {
			progressMutex.Lock()
			progress.currentURL = r.URL.String()
			progress.lastURLUpdate = time.Now()
			progressMutex.Unlock()
			displayProgress()
		}
		isFirstRequest = false

		// Logging visited URL to the file
		logDir := filepath.Join(cleanTargetString, "logs")
		logFile := filepath.Join(logDir, "crawled.txt")

		fileWriteMutex.Lock()
		defer fileWriteMutex.Unlock()

		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Error opening log file: %v\n", err)
			return
		}
		defer f.Close()

		if _, err := f.WriteString(r.URL.String() + "\n"); err != nil {
			fmt.Printf("Error writing to log file: %v\n", err)
		}
	})

	c.OnHTML("a[href], [src], link[href], object[data]", func(e *colly.HTMLElement) {
		var link string
		if href := e.Attr("href"); href != "" {
			link = e.Request.AbsoluteURL(href)
		} else if src := e.Attr("src"); src != "" {
			link = e.Request.AbsoluteURL(src)
		} else if data := e.Attr("data"); data != "" {
			link = e.Request.AbsoluteURL(data)
		}

		if link != "" {
			// Skip processing for irrelevant file types
			ext := strings.ToLower(filepath.Ext(link))
			if ext != "" && !fileTypes[ext] {
				return // Skip links that don't match the allowed file types
			}

			processLink(e, link, fileTypes, fileText, cleanTargetString, userAgent, downloadExternal, semaphore)
		}
	})
}

func downloadFile(baseURL, fileURL, cleanTargetString, userAgent string, semaphore chan struct{}) error {
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Clean and validate URL
	fileURL = strings.TrimSpace(fileURL)
	absoluteURL, err := url.Parse(fileURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	// Create request with proper headers
	req, err := http.NewRequest("GET", absoluteURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Add important headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/pdf, */*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "keep-alive")

	// Perform request
	resp, err := downloadClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Create directory structure
	parsedURL, _ := url.Parse(absoluteURL.String())
	dir := filepath.Join(cleanTargetString, getCleanDomain(parsedURL.Hostname()))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Generate filename
	originalFilename := filepath.Base(absoluteURL.Path)
	if originalFilename == "" || originalFilename == "." {
		originalFilename = time.Now().Format("2006-01-02-150405") + ".file"
	}

	ext := filepath.Ext(originalFilename)
	name := strings.TrimSuffix(originalFilename, ext)

	// Create hash for unique filename
	hasher := sha256.New()
	hasher.Write([]byte(absoluteURL.String()))
	hash := hex.EncodeToString(hasher.Sum(nil))[:8]

	filename := filepath.Join(dir, fmt.Sprintf("%s_%s%s", hash, name, ext))
	tempFilename := filename + ".tmp"

	// Check if file already exists
	if _, err := os.Stat(filename); err == nil {
		return ErrFileAlreadyDownloaded
	}

	// Create temporary file
	out, err := os.Create(tempFilename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	// Copy with progress
	pw := &progressWriter{
		total:    resp.ContentLength,
		writer:   out,
		filename: filepath.Base(filename),
	}

	_, err = io.Copy(pw, resp.Body)
	if err != nil {
		os.Remove(tempFilename)
		return fmt.Errorf("download failed: %v", err)
	}

	// Ensure file is written to disk
	if err := out.Sync(); err != nil {
		os.Remove(tempFilename)
		return fmt.Errorf("failed to sync file: %v", err)
	}

	// Close file before rename
	out.Close()

	// Rename temporary file to final name
	if err := os.Rename(tempFilename, filename); err != nil {
		os.Remove(tempFilename)
		return fmt.Errorf("failed to rename file: %v", err)
	}

	return nil
}

func getCleanDomain(domain string) string {
	reg := regexp.MustCompile("[^a-zA-Z0-9]+")
	return strings.ToLower(reg.ReplaceAllString(domain, ""))
}

func setupLogging(targetDir string) {
	logDir := filepath.Join(targetDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
		return
	}

	logFile := filepath.Join(logDir, "crawled.txt")
	if _, err := os.Create(logFile); err != nil {
		fmt.Printf("Failed to create log file: %v\n", err)
	}
}

func processLink(e *colly.HTMLElement, link string, fileTypes map[string]bool, fileText, cleanTargetString, userAgent string, downloadExternal bool, semaphore chan struct{}) {
	u, err := url.Parse(link)
	if err != nil {
		return
	}

	if !u.IsAbs() {
		baseURL := getBaseURL(e.Request)
		base, err := url.Parse(baseURL)
		if err != nil {
			return
		}
		u = base.ResolveReference(u)
		link = u.String()
	}

	// Clean up the URL
	link = strings.TrimSpace(link)
	link = strings.ReplaceAll(link, " ", "%20")

	visitedLinksMutex.Lock()
	if visitedLinks[link] {
		visitedLinksMutex.Unlock()
		return
	}
	visitedLinks[link] = true
	visitedLinksMutex.Unlock()

	// Update visited links count
	progressMutex.Lock()
	progress.visitedLinks++
	progressMutex.Unlock()
	displayProgress()

	// Try to visit the link
	e.Request.Visit(link)

	// Check if we should download this file
	ext := strings.ToLower(filepath.Ext(link))
	if ext != "" && fileTypes[ext] {
		if fileText == "" || strings.Contains(strings.ToLower(filepath.Base(link)), strings.ToLower(fileText)) {
			progressMutex.Lock()
			progress.matchingFiles++
			progressMutex.Unlock()
			displayProgress()

			// Only download if it's from allowed domain
			baseURL := getBaseURL(e.Request)
			baseDomain, _ := getBaseDomain(baseURL)
			linkDomain, _ := getBaseDomain(link)

			if downloadExternal || linkDomain == baseDomain {
				err := downloadFile(baseURL, link, cleanTargetString, userAgent, semaphore)

				progressMutex.Lock()
				if err == nil {
					progress.downloaded++
				} else if err == ErrFileAlreadyDownloaded {
					progress.alreadyDownloaded++
				} else {
					fmt.Printf("\nFailed to download %s: %v\n", link, err)
					progress.failedDownload++
				}
				progressMutex.Unlock()
				displayProgress()
			}
		}
	}
}

func getBaseURL(req *colly.Request) string {
	return fmt.Sprintf("%s://%s", req.URL.Scheme, req.URL.Host)
}

func getBaseDomain(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(parsedURL.Hostname())
	if err != nil {
		return "", err
	}

	return domain, nil
}

func checkURL(urlStr string, userAgent string) (string, bool) {
	u, err := url.ParseRequestURI(urlStr)
	if err != nil {
		for _, scheme := range []string{"http://", "https://"} {
			if validURL, isValid := tryURL(scheme+urlStr, userAgent); isValid {
				return validURL, isValid
			}
		}
	} else {
		if validURL, isValid := tryURL(u.String(), userAgent); isValid {
			return validURL, isValid
		}

		u = flipProtocol(u)
		if validURL, isValid := tryURL(u.String(), userAgent); isValid {
			return validURL, isValid
		}
	}

	return "", false
}

func tryURL(urlStr string, userAgent string) (string, bool) {
	variants := []string{
		urlStr,
		convertToWWW(urlStr),
		convertToNonWWW(urlStr),
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	for _, variant := range variants {
		req, err := http.NewRequest("HEAD", variant, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", userAgent)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			location, err := resp.Location()
			if err == nil {
				return location.String(), true
			}
		}

		if resp.StatusCode == http.StatusOK {
			return variant, true
		}
	}
	return "", false
}

func convertToWWW(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	if !strings.HasPrefix(u.Host, "www.") {
		u.Host = "www." + u.Host
	}
	return u.String()
}

func convertToNonWWW(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	u.Host = strings.TrimPrefix(u.Host, "www.")
	return u.String()
}

func flipProtocol(u *url.URL) *url.URL {
	if u.Scheme == "http" {
		u.Scheme = "https"
	} else if u.Scheme == "https" {
		u.Scheme = "http"
	}
	return u
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	if err != nil {
		return n, err
	}
	pw.written += int64(n)
	pw.downloaded += int64(n)

	if pw.total > 0 {
		percentage := float64(pw.written) / float64(pw.total) * 100
		fmt.Printf("\rDownloading %s: %.0f%% (%s/%s)\033[K",
			pw.filename,
			percentage,
			formatBytes(pw.downloaded),
			formatBytes(pw.total))
	} else {
		fmt.Printf("\rDownloading %s: %s\033[K",
			pw.filename,
			formatBytes(pw.downloaded))
	}

	return n, nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Update the displayProgress function
func displayProgress() {
	progressMutex.RLock()
	defer progressMutex.RUnlock()

	// Calculate the available terminal width (default to 80 if can't determine)
	termWidth := 80

	// Format the basic stats
	stats := fmt.Sprintf("Links: %d | Matches: %d | Down: %d | Exist: %d | Fail: %d",
		progress.visitedLinks,
		progress.matchingFiles,
		progress.downloaded,
		progress.alreadyDownloaded,
		progress.failedDownload)

	// If there's a current URL and it was updated recently
	if progress.currentURL != "" && time.Since(progress.lastURLUpdate) < 2*time.Second {
		// Truncate URL if it's too long
		maxURLLen := termWidth - len(stats) - 5 // 5 for spacing and ellipsis
		url := progress.currentURL
		if len(url) > maxURLLen && maxURLLen > 5 {
			url = "..." + url[len(url)-maxURLLen+3:]
		}
		fmt.Printf("\r%s | %s\033[K", stats, url)
	} else {
		fmt.Printf("\r%s\033[K", stats)
	}
}

func showBanner() {
	banner := `
   __________  __  ________   ________
  / ____/ __ \/  |/  /  _/ | / / ____/
 / / __/ / / / /|_/ // //  |/ / __/   
/ /_/ / /_/ / /  / // // /|  / /___   
\____/\____/_/  /_/___/_/ |_/_____/   					  
`
	fmt.Println(banner)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}
