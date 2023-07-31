---
title: "Works for Me"
url: /works-for-me
layout: wfm
type: wfm

    ######################################################################
    #     WHAT IS THIS
    ######################################################################
    # 
    # This is a so called 'Works for Me' page, as a part of ~notes bundle of
    # my page/blog listing. This describes a data details for Works for Me: 
    #   @see: http://works-for-me.github.io/
    # 
    # You are supposed to edit this file, which will be available at URI 
    # location: 
    #   @see: {BASE_URL}/works-for-me/
    # 
    # Basically, this page should describe the running environment and preferred
    # choice for Operating System, hardware machine, as well as software tools 
    # most commonly used in personas profession.
    #
    # The page is automatically updated via:
    #     =>    /themes/haxor-notes/layouts/wfm/                (layout)
    #     =>    /themes/haxor-notes/layouts/partials/wfm/       (partials)
    # 
    # You are required to set proper parameters for the page to be compiled 
    # and/or loaded via Hugo server.
    #
    # ----------------------------------------------------------------------
    # Defining 'tools' section.
    #   XXX: The 'tools' YAML properties contain page content, that will get 
    #        transformed into a beautiful single page presentation.
    # ----------------------------------------------------------------------
    # => If defined as below:
    #    -- 'This kind of definition will only create a H2 title tag with value
    #       of <list_title>. The <name> can be anything unique to other <tools:> definitions.
    #       You can refer to this definition if you want to create sort of like 
    #       <CATEGORY> that may contain <SUBCATEGORY>. The <SUBCATEGORY> can, 
    #       as you may guessed, a <CATEGORY>.'
    # tools:
    #   - name: "Main Header"
    #     list_title: "Main Header"
    # ----------------------------------------------------------------------
    # => If defined as below:
    #    -- 'This kind of definition will create a H2 title tag with value that of
    #       <list_title>. The <name> can be anything unique to other <tools:> definitions.
    #       Each line in the <description> will be a spanned paragraph in the HTML. You can
    #       use Markdown syntax.'
    # tools:
    #   - name: "Main Header"
    #     list_title: "Main Header"
    #     description:
    #       - "Some paragraph textual data here ..."
    #       - "Other paragraph that will span from the first one ..."
    #       - "You can *even use* the **Markdown** syntax for these paragraphs"
    # ----------------------------------------------------------------------
    # => If you append any of the:
    #    -- 'Appending <imageAlt> & <image> to above will create a full-width content-filling
    #       image container that refers to that <tools:> directive.'
    #    -- 'Appending <link> to above will create a URL hyperlink, pointing to that <tools:>
    #       directive, and if left omitted, no links will be generated.'
    #    -- 'It's required to omit <list_title> if you want to hyperlink the <tools:> def specs.
    #       as per description above, using <link> directive.'
    # tools:
    #   - name: "Main Header"
    #     list_title: "Main Header"
    #   - name: "Some App."
    #     link: "https://[sample]"
    #     description:
    #       - "SAMPLE_DESC_HERE"
    #     image: "https://[sample_url_image]"
    #     imageAlt: "Alt. text for Image"
    # ----------------------------------------------------------------------
    # 
    # https://github.com/duraki
    ######################################################################

    # set personal information
name: "Halis Duraki"
occupation: "Vulnerability Research Specialist, Reverse Engineer"
location: "Sarajevo, Bosnia-Herz."

    # you can set it to LinkedIn, Twitter etc.
link: "https://twitter.com/0xduraki"      # can be any HTTP(s) URL
link_text: "@0xduraki"                    # "/in/duraki" for LinkedIn

    # the 'tools' define, besides list of tools and bullet-formatted descriptions
    # that sparks interest in that tool, and also defines:
    #
    # 1*      [Title] + [Description] + [Desktop Image]
    # 
    # 2*(n)   [Tools]
    #           > Tool #1
    #           > Tool #2
tools:

  ######################################################################
  # Declaring <DESKTOP> category
  # Describe:
  #     General usage, local ENV preliminary information, Clean Desktop Screenshot 
  ######################################################################
  # 1*                      # Main Header Title Definition
  - name: "Desktop"         # Name (Environment, Software, OS ..)
    list_title: "Desktop"   # Set the section as Category, and set Category Title
    description:            
      # You can use bullets to append each new paragraph in the 'wfm' page, 
      # or you can write everything in one line, which will generate a single paragraph.
      - "As a vivid and passionate security researcher and reverse engineer, I use my macOS day to day, and this page shows core toolkit which helps me be productive and creative in my profession."
      - "Obviously Apple macOS Operating System."
      - "My laptop is a MacBook Pro (Retina, 14-Inch, Late 2022) with Apple M1 CPU and 16GB of RAM."
      
    # Desktop Screenshot, or similar
    imageAlt: "Desktop Screenshot"              # Its okay to leave it empty/omitted ...
    image: "https://works-for-me.github.io/toolkits/nikolay-garmash/desktop.png"
 


    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # Below frontmatter yaml data is used to generate list of tools/
    # softwares as seen on `Works For Me` notes.

  ######################################################################
  # Declaring <HARDWARE> category
  # Describe:
  #     Hardware Machine Device, Displays, Keyboard/Mouse setup, other setup appliances,
  #     anything related to hardware and this WFM description, Router/ISP/Switches,
  #     Apple Watch? iPhone?
  ######################################################################
  - name: "Hardware"
    list_title: "Hardware" # main title section
    list_name: # subsection title
      - "Apple MacBook Pro (14'in Retina) with M1"
    description:
      - "My setup contains two (2x) Lenovo-p27h External 2K Displays that I usually replace with my [12.9' iPad Pro (5th Gen)](https://support.apple.com/kb/SP844) when I'm on the move."
      - "For keyboard I use [White Glorious GMMK 60%](https://www.gloriousgaming.com/products/the-glorious-gmmk-compact-pre-built), and my preferred mouse of choice is [Logitech MX Masters 3](https://www.logitech.com/en-us/products/mice/mx-master-3s.html)."
      - "My daily laptop is a MacBook Pro (Retina, 14' inch), late ~2022 model with Apple M1 CPU, 16GB of RAM and 1TB of solid storage."

  ######################################################################
  # Declaring <SOFTWARE> category
  # Describe:
  #     This is only a CATEGORY definition for <SOFTWARE>. Used to create a separator
  #     between categories, and as a place to put all used softwares in this category.
  ######################################################################
  - name: "Software"
    list_title: "Software"

  ######################################################################
  # Declaring <TOOLS>+(n) in <SOFTWARE> category
  # Describe:
  #     Applications and Softwares used in day to day life, enhancing productivity,
  #     easing the daily workload, any software you'd like to credit. Since we are 
  #     omitting <list_title> property, the following will be created as a list of 
  #     tools (subcategories) under SOFTWARE category.
  ######################################################################
  - name: "iTerm"
    link: "https://iterm.com"
    description:
      - "I'm not a fan of default macOS Terminal app therefore I switch to iTerm on each macOS fresh install."
    image: "https://i.imgur.com/e3lXKwW.png"
    imageAlt: "iTerm Screenshot"

  - name: "NeoVim"
    # link: "https://iterm.com"
    description:
      - "Using NeoVim as my main IDE."
    image: ""
    imageAlt: ""

  ######################################################################
  # Declaring <ORGANIZATION> category
  # Describe:
  #     This is a CATEGORY definition for <ORGANIZATION>. Used to create a separator
  #     between categories, and as a place to put all org. apps in this category.
  ######################################################################
  - name: "Organization"
    list_title: "Organization"
  - name: "Notes"
    # link: "https://news.ycombinator.com/"
    description:
      - "The default macOS Notes app. is really good to take quick notes in a workspace-oriented collections. Here I paste my *todos*, URLs, random notes and ideas, and so on."

  ######################################################################
  # Declaring <READS> category
  # Describe:
  #     This is a CATEGORY definition for <READS>. Used to create a separator
  #     between categories, and as a place to put all common links and 
  #     news link aggregators in this category.
  ######################################################################
  - name: "Reads"
    list_title: "Reads"
  - name: "Hackernews"
    link: "https://news.ycombinator.com/"
    description:
      - "HackerNews is a social news website that showcases user-submitted technology-related news and discussions. I use it daily to discover new tech-related releases and latest information."
  - name: "Hackernews"
    link: "https://lobste.rs/"
    description:
      - "Lobste.rs is a technology-focused link aggregator that curates and shares user-submitted stories and discussions about programming, technology, and related topics. Quite similar to previous, but requires user-invitation to be able to submit and comment. Mostly focused on FreeBSD and other `*BSD` distributions."  
  
# Add <as many other> [tools/section/subsection/list_title] here.
# ... 



## Ref//
## @see: https://works-for-me.github.io/index.html (WFM/Original/Samples)
## @see: https://github.com/mykolaharmash/works-for-me (Original GitHub Inspiration Repo)
---

