# DirDar v1.0
  
## Description
<b>🏴‍☠️ bypass forbidden directories - find and identify dir listing - you can use it as directory brute-forcer as well</b><br>

### Compatabily
This tool is compatible with all kind of operating systems as long as you have GO compiler installed

## Install

You can use this command if you have Go installed and configured.

```
go get -u github.com/m4dm0e/dirdar
```

Or you can [download a release](https://github.com/m4dm0e/dirdar/releases).
To make it easier to execute you can put the directory to the binary in your environment variable `%PATH%`.

<p align="center">
    <sub>
  </sub>
  <br>
  <!--Tweet button-->
  <a href="https://twitter.com/intent/tweet?url=https%3A%2F%2Fgithub.com%2Fm4dm0e%2Fdirdar&text=DirDar%20is%20a%20tool%20that%20searches%20for%20(403-Forbidden)%20directories%20to%20break%20it%20and%20get%20dir%20listing%20on%20it." target="_blank">Share on Twitter!
  </a>
  <br><br />
  <a href="https://twitter.com/m4dm0e"><img alt="Website" src="https://img.shields.io/twitter/follow/m4dm0e.svg?style=flat-square&logo=twitter"></a>
<a href="https://www.linkedin.com/in/Albarbari/"><img alt="LinkedIn" src="https://img.shields.io/badge/LinkedIn-Mohammed%20Al%20Barbari-blue?style=flat-square&logo=linkedin"></a>
<a href="https://m4dm0e.github.io/"><img alt="Website" src="https://img.shields.io/badge/Website-m4dm0e.github.io-blue?style=flat-square&logo=google-chrome"></a>
<br />

## Tool screen:
* Linux

  <img src="statics/img/firstScreen.png" alt="linux" ></a>

* Windows

  <img src="statics/img/windows.JPG" alt="windows" ></a>
  
## Help&Flags

```
  -dirs-list string
        Comma-separated list of directories to check (default "admin,test,img,inc,includes,include,images,pictures,gallery,css,js,asset,assets,backup,static,cms,blog,uploads,files")
  -err
        If you want to show errors!(Includes 404 errors) [True-False]
  -f string
        Output format (json or csv)
  -o string
        Output file path for successful bypasses
  -only-ok
        Print out only OK (Bypassed and dir listing)
  -single string
        Only scan single target e.g (-single https://example.com/)
  -t int
        Set the timeout of the requests (default 10000)
  -threads int
        Number of threads (default 40)
  -v    Verbose output (show all requests)
  -w string
        Forbidden directories WordList (file path)
```

* Screenshot

  <img src="statics/img/help.png" alt="help" ></a>

## New Features
- Added support for reading directories from `dirs-list.txt` by default
- Added JSON/CSV output formats (`-f` flag)
- Added output file support (`-o` flag) with automatic directory creation
- Added verbose mode (`-v` flag) to show detailed request information
- Improved directory handling with default wordlist fallback
- Better error handling and file management

## Usage Examples

```bash
# Basic scan with default directories
./dirdar -single https://example.com

# Use custom wordlist and save results to JSON
./dirdar -single https://example.com -w custom-dirs.txt -f json -o results.json

# Scan with verbose output and save to CSV
./dirdar -single https://example.com -v -f csv -o results/scan.csv

# Use custom directory list
./dirdar -single https://example.com -dirs-list "admin,config,secret"
```

## Bugs found by DirDar: (Will share the write up ASAP)
* BackUp files at [MTN Group](https://hackerone.com/mtn_group?type=team) (Triaged)
* OLD php scripts to SQLi at [MTN Group](https://hackerone.com/mtn_group?type=team) (Triaged)
* OLD Files to information disclosure at [BOSCH](http://psirt.bosch.com/) (Triaged)

## Review:

[![asciicast](https://asciinema.org/a/391851.svg)](https://asciinema.org/a/391851)


