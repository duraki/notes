---
title: "Web Tricks and Tips"
---

## WebApp CLI Utils for automating stuff 

You may use and combine the below utils based on your engagement workflow. For example, once you have a nice list of HTTP History in Burp Suite Proxy, you may catalouge all of the URLs and:

* Use `jsstrings` to extract string literals out of JavaScript files of the target
* Use `qsreplace` to prepare and formulate a single attack vector on multiple arguments and URLs
* Use `waybackurls` to exfiltrate more WebApp details from the past
* Combine `waybackurls` and `anti-burl` to find relative content that is still hosted, etc.

---

[anti-burl](https://github.com/jthack/hacks/tree/master/anti-burl) - Takes URLs on stdin, prints them to stdout if they return a 200 OK.

* Used to find alive websites or these that have HTTP Server responding with 200 OK.
* Used to filter-out bad URLs from the list of URLs. 

---

[filter-resolved](https://github.com/jthack/hacks/tree/master/filter-resolved) - Take domains on stdin and output them on stdout if they resolve.

Install: `go get -u github.com/tomnomnom/hacks/filter-resolved`

* Used to find alive HTTP services that have correct DNS configured, but might be missing HTTP Responses.
* Used to filter-out bad URLs, Hostnames, Servers, and DNS from the list of URLs.
* Simply provide `domains.txt`  to stdin and pipe to `filter-resolved` CLI
  - `$ cat domains.txt | filter-resolved > resolved.txt`

---
	
[get-title](https://github.com/jthack/hacks/tree/master/get-title) - Fetch and get the title of an HTML page.

* Used to find alive HTTP services that have interesting Page Title set in HTML.
* Used to filter out duplicates based on similar or same Page Title.

---
	
[html-tool](https://github.com/jthack/hacks/tree/master/html-tool) - Take URLs or filenames for HTML documents on stdin and extract tag contents, attribute values, or comments.

Install: `go get -u github.com/tomnomnom/hacks/html-tool`

* Used to extract text contained in tags.
* Used to extract attribute values.
* Used to extract comments from the HTML page.
* Can be used to filter or exfill potential sensitive detail or new attack surface.
* Accepts URLs, or filenames for HTML documents as stdin.

---
	
[jsstrings](https://github.com/jthack/hacks/tree/master/jsstrings) - Pulls all of the string literals out of a JavaScript file.

* Used to extract all string literals defined in the Javascript files.
* These extracted string literals may contain sensitive data or may provide valuable information.
* Can be also used to quickly find string of interest in large number of strings.

---

[comb](https://github.com/jthack/hacks/tree/master/comb) - Combine the lines from two files in every combination.

* Multiple modes available during the combinatorics
* Normal mode: [1, 2] & [A, B, C] will create [1A, 1B, 1C, 2A, 2B, 2C]
* Flip mode: [1, 2] & [A, B, C] will create: [1A, 2A, 1B, 2B, 1C, 2C]
* Separator mode: [1, 2] & [A, B, C] + separator "-" will create: [1-A, 1-B, 1-C, 2-A, 2-B, 2-C]
* Used to create wordlists or combinations

---

[qsreplace](https://github.com/jthack/hacks/tree/master/qsreplace) - Accept URLs on stdin, replace all query string values with a user-supplied value.

Install: `go get -u github.com/tomnomnom/hacks/qsreplace`

* Provide input file containing all URLs with parameter queries
* Use `qsreplace` to either replace, append, or omit the query parameters
* Replacing: `https://example.com/path?one=1` -> `https://example.com/path?one=newval`
* Appending: `https://example.com/path?one=1` -> `https://example.com/path?one=1newval`
* Omitting: `https://example.com/path?one=1` -> `https://example.com/path?one=`
 
Read [Usage](https://github.com/jthack/hacks/tree/master/qsreplace) on official repository to see usage examples.

---

[urinteresting](https://github.com/jthack/hacks/tree/master/urinteresting) - Accept URLs on stdin, output the ones that look 'interesting'.

Install: `go get -u github.com/tomnomnom/hacks/urinteresting`

---

[waybackurls](https://github.com/jthack/hacks/tree/master/waybackurls) - Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for `*.domain` and output them on stdout.

Install: `go get -u github.com/tomnomnom/hacks/waybackurls`

---

https://github.com/jthack/hacks/tree/master/unisub



