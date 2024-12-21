# GoMine

A Go CLI tool to quickly crawl and mine (download) specific file types from websites.

## Limitations

- Will not work for some dynamic content sites.
- Will not work for sites with reCAPTCHA/CAPTCHA type protection.

## Installation

### Build from source (Go required)
To install / build redgrab binary from source, you need to have Go installed on your system (https://go.dev/doc/install). Once you have Go installed, you can either clone and run from source or download and install with the following command:

```terminal
go install github.com/bradsec/gomine@latest
```

## Basic Usage 

```terminal
# With URL only will default to looking for document files types
gomine --url https://thisurlexamplesite.com

# Specify individual file types
gomine --url https://thisurlexamplesite.com --filetypes ".pdf,.jpg"
```

### Predefined File Type Groups

Use with flag --filetypes  
Example using more than one group `--filetypes "images,documents"`

## Full Usage options

```terminal
  -depth int
    	The maximum depth to follow links (default 10)
  -external
    	Enable or disable downloading files from external domains (default true)
  -filetext string
    	The text to be present in the filename (optional)
  -filetypes string
    	Comma-separated list of file extensions to download (default "documents")
  -timeout int
    	The maximum time the crawling will run. (default 10)
  -url string
    	The target URL to search including http:// or https://
  -useragent string
    	The User-Agent string to use (default "random")
```

## Other Notes

### Logs
A list of the crawled/visited URLs will be stored a text file `crawled.txt` in the `logs` sub-directory of the target URL directory.

### External File Links

If files are from an external domain/url there will be sub-director of the external domain/url within the main target URL directory containing the files from that site. You can disable downloading from external links using the `--external false` flag.

