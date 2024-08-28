---
title: "Web Fuzzing Techniques"
---

Combined wordlists to use:
* Use **SecList** seed fuzz
* Use **FuzzDB** seed fuzz

**Note:** You don't have to clone `SecList` in your `$HOME` directory. Just create a symlink from your preference directory. The below command should do the trick.

```
$ ln -s ~/util/SecLists ~/SecLists
```

**gofuzz** fuzzing (fuzz javascript files to extract URLs and secrets):

Installing [gofuzz](https://github.com/nullenc0de/gofuzz) is simple via Pyhton's `venv`:

```
$ git clone git@github.com:nullenc0de/gofuzz.git
$ cd gofuzz
$ python3 -m venv path/to/venv
$ source path/to/venv/bin/activate
$ python3 -m pip install aiohttp
```

To use `gofuzz` once you have `venv`  ready, simply do the following:

```
$ echo "https://example.com/script.js" | python gofuzz.py -m both 	# to fuzz single javascript file
$ cat js_urls.txt | python gofuzz.py -m both 						# to fuzz multiple javascript files 
```

**gobuster** fuzzing (fuzz directories & subdomains):

```
cat ~/SecLists/Discovery/Web-Content/Common-DB-Backups.txt \
~/SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt \
~/SecLists/Discovery/Web-Content/PHP.fuzz.txt \
~/SecLists/Discovery/Web-Content/common.txt | gobuster fuzz -u \
https://www.utic.ba/FUZZ -b 404 -w - -k -t 30
```

You may *extend* **gobuster** *with POSIX compilant* commands. A trick to extend  `gobuster` is by using POSIX `seq` command. To exclude specific length from the output, `gobuster` requires param: `--exclude-length <len>,<len>` which would require a lot of typing in case you need various, small-byte difference between length. Use `seq` to generate such sequences, as presented in commands below:

```
$ seq -s "," 1500 1510
# 1500,1501,1502,1503,1504,1505,1506,1507,1508,1509,1510
# 
# then:
#     gobuster -u <url> --exclude-length <generated_sequence>
```

**ffuf** fuzzing (fuzz directories & files):

```
cat ~/SecLists/Discovery/Web-Content/apache.txt \
~/SecLists/Discovery/Web-Content/ApacheTomcat.fuzz.txt \
~/SecLists/Discovery/Web-Content/Common-DB-Backups.txt \
~/SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt \
~/SecLists/Discovery/Web-Content/common.txt \
~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt \
~/SecLists/Discovery/Web-Content/dirsearch.txt \
~/SecLists/Discovery/Web-Content/frontpage.txt \
~/SecLists/Discovery/Web-Content/golang.txt \
~/SecLists/Discovery/Web-Content/graphql.txt \
~/SecLists/Discovery/Web-Content/IIS.fuzz.txt \
~/SecLists/Discovery/Web-Content/Jenkins-Hudson.txt \
~/SecLists/Discovery/Web-Content/Logins.fuzz.txt \
~/SecLists/Discovery/Web-Content/nginx.txt \
~/SecLists/Discovery/Web-Content/PHP.fuzz.txt \
~/SecLists/Discovery/Web-Content/quickhits.txt \
~/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt \
~/SecLists/Discovery/Web-Content/raft-small-files-lowercase.txt \
~/SecLists/Discovery/Web-Content/spring-boot.txt \
~/SecLists/Discovery/Web-Content/RobotsDisallowed-Top1000.txt \
~/SecLists/Discovery/Web-Content/swagger.txt \
~/SecLists/Discovery/Web-Content/CMS/Django.txt \
~/SecLists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt \
~/SecLists/Discovery/Web-Content/CMS/symfony-315-demo.txt | ffuf -w - -u https://utic.ba/FUZZ -mc 200,204,301,302,307,401,405 -fs 0
```

**ffufai** fuzzing (fuzz directories via AI):

The [ffufai](https://github.com/jthack/ffufai) is an AI-powered wrapper for the popular web fuzzer ffuf. It automatically suggests file extensions for fuzzing based on the target URL and its headers, using either OpenAI or Antropic's Claude models. You need to install and configure `ffufai` first, via commands below:

```
$ git clone git@github.com:jthack/ffufai.git
$ cd ffufai
$ python3 -m venv path/to/venv
$ source path/to/venv/bin/activate
$ python3 -m pip install requests openai anthropic
$ export OPENAI_API_KEY='your-api-key-here'
$ export ANTHROPIC_API_KEY='your-api-key-here'
```

To use `ffufai`, type the commands you usually use with `ffuf`, but make sure to replace the name (use `ffufai`):

```
$ python3 ffufai.py -u https://example.com/FUZZ -w /path/to/wordlist.txt
```

**ffuf** fuzzing for *.svn/.git/[common_php]*:

```
cat ~/SecLists/Discovery/Web-Content/CMS/symphony-267-xslt-cms.txt \
~/SecLists/Discovery/Web-Content/CMS/symfony-315-demo.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/symfony.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/all.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/all-dirs.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/context/error.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/context/index.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/context/install.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/context/readme.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/context/root.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/context/setup.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/context/test.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/context/debug.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/context/admin.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Conf/conf.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Conf/config.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Conf/htaccess.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Database/inc.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Database/ini.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Database/sql.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Database/xml.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Language/php.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Language/js.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Language/html.txt \
~/SecLists/Discovery/Web-Content/SVNDigger/cat/Language/jar.txt \
~/SecLists/Discovery/Web-Content/api/actions-lowercase.txt \
~/SecLists/Discovery/Web-Content/Common-DB-Backups.txt \
~/SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt \
~/SecLists/Discovery/Web-Content/PHP.fuzz.txt \
~/SecLists/Discovery/Web-Content/common.txt | ffuf -w - -u https://utic.ba/FUZZ -mc 200,204,301,302,307,401,403,405 -fs 0
```

### Fuzz List

```
# => Symfony / Laravel Framework
Discovery/Web-Content/CMS/symphony-267-xslt-cms.txt
Discovery/Web-Content/CMS/symfony-315-demo.txt
Discovery/Web-Content/SVNDigger/symfony.txt

# => many stuff
Discovery/Web-Content/SVNDigger/all.txt
Discovery/Web-Content/SVNDigger/all-dirs.txt
Discovery/Web-Content/SVNDigger/context/error.txt
Discovery/Web-Content/SVNDigger/context/index.txt
Discovery/Web-Content/SVNDigger/context/install.txt
Discovery/Web-Content/SVNDigger/context/readme.txt
Discovery/Web-Content/SVNDigger/context/root.txt
Discovery/Web-Content/SVNDigger/context/setup.txt
Discovery/Web-Content/SVNDigger/context/test.txt
Discovery/Web-Content/SVNDigger/context/debug.txt
Discovery/Web-Content/SVNDigger/context/admin.txt
Discovery/Web-Content/SVNDigger/cat/Conf/conf.txt
Discovery/Web-Content/SVNDigger/cat/Conf/config.txt
Discovery/Web-Content/SVNDigger/cat/Conf/htaccess.txt
Discovery/Web-Content/SVNDigger/cat/Database/inc.txt
Discovery/Web-Content/SVNDigger/cat/Database/ini.txt
Discovery/Web-Content/SVNDigger/cat/Database/sql.txt
Discovery/Web-Content/SVNDigger/cat/Database/xml.txt
Discovery/Web-Content/SVNDigger/cat/Language/php.txt
Discovery/Web-Content/SVNDigger/cat/Language/js.txt
Discovery/Web-Content/SVNDigger/cat/Language/html.txt
Discovery/Web-Content/SVNDigger/cat/Language/jar.txt
Discovery/Web-Content/api/actions-lowercase.txt

# => ruby
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/webservers-appservers/Ruby_Rails.txt

# => mostly php stuff
Discovery/Web-Content/Common-DB-Backups.txt # => good stuff
Discovery/Web-Content/Common-PHP-Filenames.txt # => good stuff
Discovery/Web-Content/PHP.fuzz.txt # => good for phpmyadmins
Discovery/Web-Content/common.txt # => usual stuff like .git/.rc-s/dotfiles
https://raw.githubusercontent.com/xajkep/wordlists/master/discovery/php_files_only.txt # => more php

# => mostly api
Discovery/Web-Content/swagger.txt # => find swagger location
Discovery/Web-Content/api/api_endpoints.txt # => api endpoints

# => all web extensions are available below:
Discovery/Web-Content/web-extensions.txt
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/filename-dirname-bruteforce/CommonWebExtensions.txt

# => also this one for backups
https://raw.githubusercontent.com/xajkep/wordlists/master/discovery/backup_files_only.txt
https://raw.githubusercontent.com/xajkep/wordlists/master/discovery/log_files_only.txt

# => for login/admin pages
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/login-file-locations/Logins.txt
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/login-file-locations/cfm.txt
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/login-file-locations/html.txt
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/login-file-locations/jsp.txt
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/login-file-locations/php.txt

# => webservers
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/webservers-appservers/Apache.txt 
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/webservers-appservers/ApacheTomcat.txt

# => other ...
https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/UnixDotfiles.txt
```



