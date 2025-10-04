---
title: "Source Code Audit"
---

### Workflow

Auditing application source codebase for potential security vulnerabilities is a tedious task, and it requires excellent knowledge in various topics, business domain of the application, different languages used in its' implementations, as well as having overall approach taken by the tested/analyzed application or the development team. Therefore, the auditing of the codebase should be done carefully and with utmost respect and keen to details.

During the source code audit engagements, I'm using various specific software that ease the analysis period. Besides having the [__language-specific__](#language-specific) static code analysis tools and static code checkers/linters (with corresponding patterns) that are of great importance during the analysis period, depending on the environment the application is running or being developed on, the utility of choice differs.

Check [this GitHub repository](https://github.com/sigp/solidity-security-blog) for optional, cryptocurrency-related (ie. *'Solidity Security'*) basis ground for testing and exploiting common smart contract vulnerabilities and known attacks.

### Software

**Codecrumbs:** For example, the open-source software [codecrumbs](https://github.com/Bogdan-Lyashenko/codecrumbs) can help aiding the learning phase of how the application is designed, tied to its business domain and corresponds to its functionality. It's overall great tool for exploring unknown codebase as it works by analyzing the source code and building the visual representation of the application business domain logic with its core approach. The final result is a codecrumb-comment of the codebase depending on its states, reflected by the visual client on the fly.

{{< galleries >}}
    {{< gallery src="https://codecrumbs.io/external/img/common/app-ui-1.png" title="Image Caption" >}}
    {{< gallery src="https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fcdn-images-1.medium.com%2Fmax%2F800%2F1%2AOTbzqtV0UxTq_OLkoMfHMw.gif" title="Image Cpation" >}}
{{< /galleries >}}

**Heystack:** Another great tool that I use quite often during source code audit is a [Haystack](https://haystackeditor.com) Code Editor. This tool helps me visualize and, when testing, edit the code by having it laid out on an infinite canvas. Haystack is something between the IDE and mindnote, code-oriented whiteboard, but it works in a way that it puts relevant file or a function code of the audited codebase, by putting it on a 2D digital whiteboard. The code blocks that is being analysed is automatically draws connected between the each interconnected block, and navigating and/or editing the files redraws the connection arrows. This way, the Haystack Editor can be used to draw the model of how some code might work, and graph relevant components in a connected manner. The [Haystack Editor](https://github.com/haystackeditor/haystack-editor) is free and open-source, and it is based orignally on VSCode Editor.

![](https://i.imgur.com/CeuVPqF.gif)

**AppMap** for VSCode**:** I'd gladly recommend [AppMap](https://marketplace.visualstudio.com/items?itemName=appland.appmap) extension for VSCode which is an AI-driven chat with a deep understanding of the code, that can aid you understanding contextual states and provide information how the application works, but due to potential [AI telemetry](https://appmap.io/blog/2021/01/12/using-appland-and-vscode-to-ramp-up-on-a-codebase/) I discourage anyone to use this technique on any closed-source and/or enterprise software. Instead, AppMap may come handy when you are engaging on open-source codebase, and you can use it to understand unfamiliar codebases. AppMap works in a way that it automatically records and diagrams software behavior by executing relevant source code test cases integrated and available in the analysed codebase. Therefore, the end result is an AppMap Diagrams providing you a way to walk through automatically generated white-board right in the VSCode. Learn more about AppMap [usage & introduction](https://appmap.io/blog/2021/01/12/using-appland-and-vscode-to-ramp-up-on-a-codebase/) on official website.

![](https://i.imgur.com/CbvaDYl.gif)

---

Other enterprise solutions exists as well (ie. [CodeSee](https://www.codesee.io)) among others, but I've not tested them personally.

**Matching Pattern Lists**

Having a good matching patterns that provides the linting and/or static analysis tools is also a huge requirement if you want to dvel into source code audit or analysis process. Since most of the static code analysis software is based on extracting relevant code that matches the code function blocks or function patterns (usually indicating a potential source of a security issue or an attack surface), these will surely provide a better output results as long as the pattern matching list is good. 

Lets say you have a C/C++ codebase that you want to audit. The matching pattern for a static code analysis software could search for `memcpy`, where the tested codebase calls it with a buffer size provided somewhere else alongside the codebase, through the user provided input on the `buffer` size. It's important to keep updating and adding new matching patterns for different languages you've preivously engaged on, since you might discover new "__triggering__" functions that is exploitable, or some other attack surface not typicaly found via default lists. It's best to keep this matching patterns `git`-__tracked__ somewhere on your GitHub, therefore having the list by hand whenever you need it.

### Language Specific

For **PHP/x.xx** Server-Side Scripting Language, additional notes are available in [PHP Source Code Analysis](/php-source-code-analysis) and [PHP Filesystem Functions](/php-filesystem-functions).

---

For **Java** Language, mostly related for web-application, additional notes are available in [Java Source Code Analysis](/java-source-code-analysis).

---

For **Python** Language, there is [pyt](https://github.com/python-security/pyt) - a static analysis tool for detecting security vulnerabilities in Python Web Applications. You may also take a look at [PyCQA/bandit](https://github.com/PyCQA/bandit), a security linter tool designed to find common security issues in Python code.

---

For **GoLang** code audits and reviews, read out "Secfault Security Report, published for 1Password Code Audit" in references below.

---

Misc Tools:

* [opengrep/opengrep](https://github.com/opengrep/opengrep) - Static code analysis engine to find security issues in code
* [google/osv-scanner](https://github.com/google/osv-scanner) - Vulnerability Scanner written in Go which uses data provided by osv.dev


---

Reference to openly published reports:

- [X41 D-Sec "Source Code Audit of BIND 9 for Internet Systems Corporation"](https://www.x41-dsec.de/static/reports/X41-ISC-BIND9-Code-Audit-Public-Report-2024-02-13.pdf)
- [X41 D-Sec "Source Code Audit on libjpeg-turbo for OSTIF"](https://www.x41-dsec.de/static/reports/X41-OSTIF-libjpegturbo-Audit-20230712-Public.pdf)
- [X41 D-Sec "Code Review of the Go TUF Implementation for OSTIF"](https://www.x41-dsec.de/static/reports/X41-go-tuf-Audit-2023-Final-Report-PUBLIC.pdf)
- [X41 D-Sec "Source Code Audit on simplejson for OSTIF"](https://www.x41-dsec.de/static/reports/X41-OSTIF-simplejson-CodeRview-2023-04-18.pdf)
- [X41 D-Sec "Source Code Audit on Git for OSTIF"](https://www.x41-dsec.de/static/reports/X41-OSTIF-Gitlab-Git-Security-Audit-20230117-public.pdf)
- [Secfault Security "Security Assessment for 1Password"](https://bucket.agilebits.com/security/SecfaultSecurity_Report_OP_Security_Assessment_v1.0.pdf)