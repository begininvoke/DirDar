package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var SingleScan = false

/*
This colors code from -> https://github.com/ethicalhackingplayground/Zin/blob/master/zin.go
*/
var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"
var Yellow = "\033[33m"
var Blue = "\033[34m"
var Purple = "\033[35m"
var Cyan = "\033[36m"
var Gray = "\033[37m"
var White = "\033[97m"
var Dark = "\033[90m"
var clear map[string]func() //create a map for storing clear funcs

// Add package-level variables
var (
	outputFormat    string
	outputFile      *os.File
	ForbiddenList   []string
	verbose         bool
	defaultDirsFile = "dirs-list.txt" // default file for directories list
	successCount    int               // track successful bypasses
)

func init() {
	clear = make(map[string]func()) //Initialize it
	clear["linux"] = func() {
		cmd := exec.Command("clear") //Linux example, its tested
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	clear["windows"] = func() {
		cmd := exec.Command("cmd", "/c", "cls") //Windows example, its tested
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	if runtime.GOOS == "windows" {
		Reset = ""
		Dark = ""
		Red = ""
		Green = ""
		Yellow = ""
		Blue = ""
		Purple = ""
		Cyan = ""
		Gray = ""
		White = ""
	}
}

/////////////////////////////////////////////////////////

// //| Clear the terminal screen ...
func scre3n() {
	/////| This code from :-> https://stackoverflow.com/questions/22891644/how-can-i-clear-the-terminal-screen-in-go
	value, ok := clear[runtime.GOOS] //runtime.GOOS -> linux, windows, darwin etc.
	if ok {                          //if we defined a clear func for that platform:
		value() //we execute it
	}
	/* No need to exit the app if the tool cannot clear the screen :D
	else { //unsupported platform

		//panic("Your platform is unsupported! I can't clear terminal screen :(")
	}
	*/
}

// //| Error handling function ...
func err0r(oNe error, msg string) {
	if oNe != nil {
		scre3n()
		fmt.Println("\n\n		[x] - ", Red, msg, White, "\n\n")
		os.Exit(0)
		return
	}
}

// /| This function is to find the forbidden directories .....
func ForbidFinder(domain string, wl []string, nf bool, TimeOut int, OnlyOk bool, isItSingle bool) {

	if isItSingle {
		fmt.Println("			-[ YOUR TARGET : ", domain, " ]-\n\n")
	}
	timeout := time.Duration(TimeOut * 1000000)
	tr := &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}

	///| IF STATMENT |\\\
	Door := fmt.Sprintf("%s/%s/", domain, "DirDarWithRandomString")
	reQ, err := client.Get(Door)
	if err != nil {
		return
	}
	if reQ.StatusCode == 403 {
		return
	}

	for _, WordList := range wl {
		FullUrl := fmt.Sprintf("%s/%s/", domain, WordList)
		reQ, err := client.Get(FullUrl)
		if err != nil {
			return
		}
		defer reQ.Body.Close()
		if reQ.StatusCode == 403 {
			do3r(domain, WordList, TimeOut, OnlyOk)
		} else if reQ.StatusCode == http.StatusOK {
			bodyBytes, err := ioutil.ReadAll(reQ.Body)
			if err != nil {
				return
			}
			bodyString := string(bodyBytes)
			Directory1StCase := "Index of /" + WordList
			DirectorySecCase := "Directory /" + WordList
			Directory3RdCase := "Directory listing for /" + WordList
			if strings.Contains(bodyString, Directory1StCase) || strings.Contains(bodyString, DirectorySecCase) || strings.Contains(bodyString, Directory3RdCase) {
				fmt.Println(White, "  [+] -", Green, " Directory listing ", White, "[", Cyan, FullUrl, White, "]", "Response code ", "[", reQ.StatusCode, "]")

			}
		} else {
			if nf {
				fmt.Println(Purple, "   [X] NOT FOUND : ", White, "[", Blue, FullUrl, White, "]", " With code -> ", "[", Red, reQ.StatusCode, White, "]")
			} else {
			}
		}
	}

}

// Add new struct for JSON/CSV output
type ScanResult struct {
	Target     string `json:"target"`
	Path       string `json:"path"`
	Payload    string `json:"payload"`
	StatusCode int    `json:"status_code"`
	Timestamp  string `json:"timestamp"`
}

// Modify do3r function to handle output
func do3r(domain string, path string, TimeOut int, OnlyOk bool) {
	// Reset successCount for each directory test
	successCount = 0
	ByPass := []string{"%20" + path + "%20/", "%2e/" + path, "./" + path + "/./", "/" + path + "//", path + "..;/", path + "./", path + "/", path + "/*", path + "/.", path + "//", path + "?", path + "???", path + "%20/", path + "/%25", path + "/.randomstring"}
	ByPassWithHeader := []string{"X-Custom-IP-Authorization", "X-Originating-IP", "X-Forwarded-For", "X-Remote-IP", "X-Client-IP", "X-Host", "X-Forwarded-Host"}
	timeout := time.Duration(TimeOut * 1000000)
	tr := &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}
	FinalLook := fmt.Sprintf("%s/%s/", domain, path)
	FinalLookToReq := fmt.Sprintf("%s/%s/", domain, path)

	// Only show initial 403 in verbose mode and when not OnlyOk
	if verbose && !OnlyOk {
		fmt.Println(White, "	[+]", Cyan, "- Testing", White, "[", Blue, FinalLook, White, "]")
	}

	totalTests := len(ByPassWithHeader) + len(ByPass)

	for t0Bypass2 := range ByPassWithHeader {
		//FullUrl := fmt.Sprintf("%s/%s", domain, )
		//reQ, err := client.Get(FullUrl)
		reQ, err := http.NewRequest("GET", FinalLookToReq, nil)
		if err != nil {
			panic(err)
		}
		reQ.Header.Add(ByPassWithHeader[t0Bypass2], "127.0.0.1")
		resp, err := client.Do(reQ)
		if err != nil {
			//panic(err)
			return
		}
		if resp.StatusCode == http.StatusOK {
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return
			}
			bodyString := string(bodyBytes)
			Directory1StCase := "Index of /" + path
			DirectorySecCase := "Directory /" + path
			Directory3RdCase := " - " + path
			if strings.Contains(bodyString, Directory1StCase) || strings.Contains(bodyString, DirectorySecCase) || strings.Contains(bodyString, Directory3RdCase) {
				// Always show successful bypasses
				logBypass(FinalLook, ByPassWithHeader[t0Bypass2]+": 127.0.0.1", resp.StatusCode)
			}
			//finalWG.Done()
			//time.Sleep(10 * time.Second)

			// Add result handling for successful bypasses
			result := ScanResult{
				Target:     domain,
				Path:       path,
				Payload:    ByPassWithHeader[t0Bypass2] + ": 127.0.0.1",
				StatusCode: resp.StatusCode,
				Timestamp:  time.Now().Format(time.RFC3339),
			}

			// Handle different output formats
			if outputFormat == "json" {
				jsonData, _ := json.Marshal(result)
				if outputFile != nil {
					fmt.Fprintln(outputFile, string(jsonData))
				}
			} else if outputFormat == "csv" {
				csvLine := fmt.Sprintf("%s,%s,%s,%d,%s\n",
					result.Target, result.Path, result.Payload,
					result.StatusCode, result.Timestamp)
				if outputFile != nil {
					fmt.Fprint(outputFile, csvLine)
				}
			}
		} else {
			if !OnlyOk && verbose {
				fmt.Println(White, "	  [-]", Yellow, " - FAILED : payload", White, "[", Green, ByPassWithHeader[t0Bypass2], ": 127.0.0.1", White, "] ", Blue, FinalLook, White, " -> Response status code [", Red, resp.StatusCode, White, "]")
			}
		}
	}
	for t0Bypass := range ByPass {
		//	finalWG.Add(1)
		//qs := url.QueryEscape(ByPass[t0Bypass])
		FullUrl := fmt.Sprintf("%s/%s", domain, ByPass[t0Bypass])
		//u, err := url.Parse(qs)
		reQ, err := client.Get(FullUrl)
		if err != nil {
			return
			//panic(err)
		}
		defer reQ.Body.Close()
		if reQ.StatusCode == http.StatusOK {
			bodyBytes, err := ioutil.ReadAll(reQ.Body)
			if err != nil {
				return
			}
			bodyString := string(bodyBytes)
			Directory1StCase := "Index of /" + path
			DirectorySecCase := "Directory /" + path
			Directory3RdCase := " - " + path
			if strings.Contains(bodyString, Directory1StCase) || strings.Contains(bodyString, DirectorySecCase) || strings.Contains(bodyString, Directory3RdCase) {
				// Always show successful bypasses
				logBypass(FullUrl, ByPass[t0Bypass], reQ.StatusCode)
			}
			//stime.Sleep(10 * time.Second)
		} else {
			if !OnlyOk && verbose {
				fmt.Println(White, "	  [-]", Yellow, " - FAILED : payload", White, "[", Green, ByPass[t0Bypass], White, "] ", Blue, FullUrl, White, " -> Response status code [", Red, reQ.StatusCode, White, "]")
			}
		}
	}

	// Add summary at the end if verbose
	if verbose {
		fmt.Printf("\nCompleted testing %s: %d/%d bypasses successful\n",
			FinalLook, successCount, totalTests)
	}
}

// Helper function to log successful bypass
func logBypass(url, payload string, statusCode int) {
	successCount++ // Increment the package-level counter
	fmt.Printf("\n%s	  [+] - BYPASSED : %s -> [%d]\n",
		Yellow, url, statusCode)
}

func worker(domain chan string, wg *sync.WaitGroup, wl []string, nf bool, TimeOut int, OnlyOk bool) {
	defer wg.Done()
	for b := range domain {
		ForbidFinder(b, wl, nf, TimeOut, OnlyOk, SingleScan)
	}
}

func bann3r() {
	scre3n()
	const banner = `
______ _     ______           
|  _  (_)    |  _  \          
| | | |_ _ __| | | |__ _ _ __ 
| | | | | '__| | | / _  | '__|
| |/ /| | |  | |/ / (_| | |   
|___/ |_|_|  |___/ \__,_|_|  v1.0  
`
	const about = `
	Author : Mohammed Al-Barbari
		Twitter : @m4dm0e	
	      GrodRiket security team
		Love from :`
	var from = Red + "Ye" + White + "me" + Dark + "n"
	fmt.Println(banner, about, from, Reset, "\n\n")

}
func h3lp() {
	fmt.Println("\n", White, "	[-]", Red, "No input provided ", White, "(Run the tool again with --help flag for more information .)\n\n")
	os.Exit(0)
}
func main() {
	bann3r()
	var wg sync.WaitGroup
	DomainsList := make(chan string)

	// Add new flags
	var dirsList string
	flag.StringVar(&dirsList, "dirs-list", "", "Comma-separated list of directories to check")
	var wl string
	flag.StringVar(&wl, "w", "", "Forbidden directories WordList (file path)")

	// Use the package-level outputFormat
	flag.StringVar(&outputFormat, "f", "", "Output format (json or csv)")

	var outputPath string
	flag.StringVar(&outputPath, "o", "", "Output file path for successful bypasses")

	////| Requests TimeOut
	var TimeOut int
	flag.IntVar(&TimeOut, "t", 10000, "Set the timeout of the requests (Millisecond)")
	var con int
	flag.IntVar(&con, "threads", 40, "Number of threads")

	showErr := flag.Bool("err", false, "If you want to show errors!(Includes 404 errors) [True-False]")

	//var OnlyOK string
	//flag.StringVar(&OnlyOK, "only-ok", "", "Print out only OK (Bypassed and dir listing) ")
	OnlyOK := flag.Bool("only-ok", false, "Print out only OK (Bypassed and dir listing) ")

	// var OnlyBypass string
	// flag.StringVar(&OnlyBypass, "to-bypass", "", "Use this option with sites list [If you already have forbidden dirs] e.x(-to-bypass Forbiddens.txt)")

	var SingleSite string
	flag.StringVar(&SingleSite, "single", "", "Only scan single target e.g (-single https://example.com/)")

	// Add verbose flag
	flag.BoolVar(&verbose, "v", false, "Verbose output (show all requests)")

	flag.Parse()
	// showErr = strings.ToLower(showErr)
	if !verbose {
		*showErr = true
	}
	if !checkSiteIsUp(SingleSite) {
		fmt.Printf("🚨 Host %s is unreachable, aborting scan\n", SingleSite)
		return
	}
	// Handle directories list
	if wl == "" {
		if dirsList != "" {
			// Use provided comma-separated list
			ForbiddenList = strings.Split(dirsList, ",")
		} else {
			// Try to read from default file
			dirs, err := readDirsFromFile(defaultDirsFile)
			if err != nil {
				// Fall back to default hardcoded list
				ForbiddenList = []string{
					"admin", "test", "img", "inc", "includes",
					"include", "images", "pictures", "gallery",
					"css", "js", "asset", "assets", "backup",
					"static", "cms", "blog", "uploads", "files",
				}
			} else {
				ForbiddenList = dirs
			}
		}
	} else {
		// Read from provided wordlist file
		dirs, err := readDirsFromFile(wl)
		if err != nil {
			finalErr := fmt.Sprintf("Error reading wordlist file: %s", wl)
			err0r(err, finalErr)
		}
		ForbiddenList = dirs
	}

	// Handle output file
	if outputPath != "" {
		if err := ensureDir(outputPath); err != nil {
			finalErr := fmt.Sprintf("Error creating output directory: %v", err)
			err0r(err, finalErr)
		}

		var err error
		outputFile, err = os.Create(outputPath)
		if err != nil {
			finalErr := fmt.Sprintf("Error creating output file: %s", outputPath)
			err0r(err, finalErr)
		}
		defer outputFile.Close()

		// Write header for CSV format
		if outputFormat == "csv" {
			_, err := outputFile.WriteString("target,path,payload,status_code,timestamp\n")
			if err != nil {
				finalErr := fmt.Sprintf("Error writing CSV header: %v", err)
				err0r(err, finalErr)
			}
		}
	}

	if SingleSite == "" {
		for c := 0; c <= con; c++ {
			wg.Add(1)
			go worker(DomainsList, &wg, ForbiddenList, *showErr, TimeOut, *OnlyOK)
		}
		sc := bufio.NewScanner(os.Stdin)
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			go func() {
				for sc.Scan() {
					texted := sc.Text()
					DomainsList <- texted
				}

				close(DomainsList)
			}()

		} else {
			h3lp()
		}

		wg.Wait()

	} else {
		ForbidFinder(SingleSite, ForbiddenList, *showErr, TimeOut, *OnlyOK, true)
	}

}

// Helper function to read directories from file
func readDirsFromFile(filepathS string) ([]string, error) {
	appPath, err := os.Executable()
	if err != nil {
		fmt.Printf("Failed to get application path: %v\n", err)
		return nil, err
	}
	appDir := filepath.Dir(appPath)
	defaultLocalPath := filepath.Join(appDir, filepathS)
	defaultGlobalPath := "/usr/local/bin/" + filepathS
	fmt.Printf("Checking for  in %s\n and %s\n", appDir, defaultGlobalPath)
	// Check if the file exists in the application's directory
	configfilepath := defaultLocalPath
	if _, err := os.Stat(configfilepath); os.IsNotExist(err) {
		// If not found in the app directory, fall back to /usr/local/bin
		fmt.Printf(" not found in %s, trying %s\n", appDir, defaultGlobalPath)
		configfilepath = defaultGlobalPath
	}
	content, err := ioutil.ReadFile(configfilepath)
	if err != nil {
		return nil, err
	}
	dirs := strings.Split(strings.TrimSpace(string(content)), "\n")
	// Remove empty lines and trim spaces
	var cleanDirs []string
	for _, dir := range dirs {
		if trimmed := strings.TrimSpace(dir); trimmed != "" {
			cleanDirs = append(cleanDirs, trimmed)
		}
	}
	return cleanDirs, nil
}

// Helper function to ensure directory exists
func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	return nil
}
func checkSiteIsUp(url string) bool {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Head(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider any 2xx/3xx status as "up"
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		fmt.Printf("✅ Host is reachable (%s)\n", resp.Status)
		return true
	}
	return false
}
