---
title: "Works for Me"
url: /works-for-me
layout: wfm
type:
  wfm

  ######################################################################
  #     WHAT IS THIS
  ######################################################################
  #
  # This is a so called 'Works for Me' page, as a part of ~notes bundle of
  # 0xduraki blog listing. This describes a data details for Works for Me:
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
occupation: "Security Researcher, Reverse Engineer"
location:
  "Sarajevo, Bosnia-Herzegovina 🇧🇦"

  # you can set it to LinkedIn, Twitter etc.
link: "https://twitter.com/in/duraki" # can be any HTTP(s) URL
link_text:
  "/in/duraki" # "/in/duraki" for LinkedIn


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
  - name: "Desktop" # Name (Environment, Software, OS ..)
    list_title: "Desktop" # Set the section as Category, and set Category Title
    description:
      # You can use bullets to append each new paragraph in the 'wfm' page,
      # or you can write everything in one line, which will generate a single paragraph.
      - "As a vivid and passionate security researcher and reverse engineer, I
        use my macOS day to day, and this page shows core toolkit which helps me
        be productive and creative in my profession."
      - "Obviously Apple macOS Operating System."
      - "My laptop is a MacBook Pro (Retina, 14-Inch, Late '21) with Apple M1
        CPU and 16GB of RAM."

    # Desktop Screenshot, or similar
    imageAlt: "Desktop Screenshot" # Its okay to leave it empty/omitted ...
    image: "https://i.imgur.com/U3xMsPL.jpg"

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
      - "My setup contains dualscreen (2x) [Lenovo-p27h External 2K
        Displays](https://www.lenovo.com/in/en/accessories-and-monitors/monitors/professional/P27h-20D19270QP127inch-Monitor-HDMI/p/61E9GAR6WW?orgRef=https%253A%252F%252Fwww.google.com%252F)
        that I usually replace with my [12.9' iPad Pro (5th
        Gen)](https://support.apple.com/kb/SP844) when I'm on the move."
      - "For keyboard I use [White Glorious GMMK
        60%](https://www.gloriousgaming.com/products/the-glorious-gmmk-compact-pre-built),
        and my preferred mouse of choice is [Logitech MX Masters
        3](https://www.logitech.com/en-us/products/mice/mx-master-3s.html)."
      - "My daily laptop is a MacBook Pro (Retina, 14' inch), late '21 model
        with Apple M1 CPU, 16GB of RAM and 1TB of solid storage."
      - "When I'm on the move, I prefer using my 12.9 iPad Pro (5th Gen) with
        [Magic Keyboard
        Folio](https://www.apple.com/shop/product/MQDP3LL/A/magic-keyboard-folio-for-ipad-10th-generation-us-english),
        in combination with my iPhone 11 Max Pro (1TB) and my [Apple Watch
        Ultra](https://www.apple.com/apple-watch-ultra/) which I absolutely love
        to bring on my holiday trips and hikings."

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
      - "I'm not a fan of default macOS Terminal app therefore I switch to iTerm
        on each macOS instance. I'm using my custom color scheme, as well as
        custom `zsh` prompt, with my very own startup ascii graphics."
    image: "https://i.imgur.com/FPPQYfH.png"
    imageAlt: "iTerm Screenshot"
  - name: "tmux"
    description:
      - "This is literally the best tool ever. It allows you to create terminal
        sessions, windows, panes all within single tty. I can easily switch
        between each and also detach from sessions which may contain long
        running tasks."

  - name: "Nova"
    link: "http://nova.app"
    description:
      - "Usually I prefer **NeoVim** but lately I've been using **Nova** from
        Panic as my main IDE and development editor of choice. It is quite
        robust and works natively on MacOS, plus you get handy of extensions
        that you may use for different type of projects and specificiations.
        Unlike other similar alternative, Nova is not too expensive (100$ USD)
        and it works out of the box for most projects."

  - name: "NeoVim"
    # link: "https://iterm.com"
    description:
      - "Using NeoVim as my secondary editor, integrated with iTerm and my
        `tmux` environment. I have custom color scheme that looks beautiful and
        matches my iTerm theme. I'm sucker for [LunarVim](http://lunarvim.org),
        which I used extensively to configure my NeoVim instance. I rarely use
        NeoVim nowadays, except to quickly edit some files."
    image: "https://i.imgur.com/4TBbmCx.png"
    imageAlt: "NeoVim w/ custom LunarVim - Startup"

  - name: "Safari"
    description:
      - "I'm using Safari to browse interenet websites, research new topics,
        develop my frontend activities and do other web related work."

  - name: "Airmail Business"
    description:
      - "Possibly the best eMail client available natively for MacOS, iPadOS and
        iOS. I highly recommend Airmail for Business if your daily acitivities
        include managing multiple eMail addresses, sending invoices, replying on
        business offers and so on."

  - name: "Worth Mentioning 🎉"
    description:
      - "[Sequel Ace](https://sequel-ace.com),
        [AppCleaner](https://freemacsoft.net/appcleaner/), [Tangent
        Notes](https://www.tangentnotes.com), WiFi Explorer, Sleeve 2, ..."

  - name: "Images & Video"
    list_title: "Images & Video"
  - name: "Sketch"
    link: "https://www.sketch.com"
    description:
      - "The only UI editing software that I trust, and have been using for
        years. Highly recommended for all UI/UX designers."
  - name: "Shapr3D"
    link: "http://shapr3d.com"
    description:
      - "I rarely design anything in 3D, but when I do, I'm opting out for
        Shapr3D which is also available on iPad. It allows me to quickly
        three-dimensionaly design any kind of projection I've imagined. It's a
        bit pricey and subscription based, but it's well worth the price."
  - name: "VN Video Editor"
    description:
      - "I use VN Video Editor as a my main video editor which I mostly use when
        editing demo videos for my [Instagram](https://instagram.com/e34.brt)
        account."
  - name: "Want to buy 🤑"
    description:
      - "[OptiClean](https://opticlean.io)"

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
      - "The default macOS Notes app. is really good to take quick notes in a
        workspace-oriented collections. Here I paste my *todos*, URLs, random
        notes and ideas, and so on."

  - name: "SnippetsLab"
    description:
      - "It's not strange to catch me using
        [SnippetsLab](https://www.renfei.org/snippets-lab/) which usually
        contains temporary trash notes that I might need for future reference,
        depending what my workflow is. I rarely use it to actually store
        long-term snippets for the development stuff."

  - name: "Rayon"
    link: "https://github.com/Lakr233/Rayon"
    description:
      - "I use Rayon to manage and organise my Virtual Private Servers, Nodes,
        Controllers, and other network devices through multiple datacenters and
        providers. It's quite simple to configure and use, and you can sync your
        settings to iCloud."
    image: "https://i.imgur.com/NY63PmZ.png"
    imageAlt: "Rayon App. Preview (Blurred)"

  - name: "Utils"
    list_title: "Utils"
  - name: "Tiles"
    link: "https://freemacsoft.net/tiles/"
    description:
      - "Deserved place in this list - once you try Tiles, you will never stop
        using it. Tiles allows you to reorganize windows by dragging them to the
        edges of the screen, similar to what WindowsNT does natively."
  - name: "Itsycal"
    link: "https://www.mowglii.com/itsycal/"
    description:
      - "Cute and small calendar living in your macOS menubar, good for glancing
        over your meetings and events."
  - name: "Syncalicious"
    description:
      - "I've just started using this utility but I absolutely love the way it
        works. It allows you to sync all of your macOS applications to your
        iCloud, and use the synced configuration on all your other Macs."
  - name: "Amphetamine"
    description:
      - "Keeps your MacOS awake, even if lid is closed. Quite configurable and
        also free."
  - name: "Command X"
    link: "https://sindresorhus.com/command-x"
    description:
      - "Tries to bring WindowsOS **`Ctrl+X`** shortcut on your macOS."

  ######################################################################
  # Declaring <SW_FULL> category
  # Describe:
  #     This is a CATEGORY definition for <SW_FULL>. Used to create a separator
  #     between categories, and as a place to display all softwares installed and
  #     used, per each category of the software.
  #
  #     The 'collapsible' flag declares whether the given key array should be
  #     rendered in '<details>' HTML tag which provides a collapsable UI. If the
  #     collapsible is set to 'true', all keys in 'description' will be collapsed
  #     and user will need to click on the 'name' to expand the collapsable
  #     section.
  #
  #     The 'description' array is used to describe both the CATEGORY and the
  #     SOFTWARE_LIST in a format '<CATEGORY>:<SOFTWARE_LIST>'. By using this
  #     format, the `themes/.../partials/wfm/tool_wfm.html` will now use the
  #     ":" (semicolon) delimiter to split CATEGORY and the SOFTWARE_LIST, and
  #     render them beautifuly.
  #
  #     Note that, if you want hyperlink a specific software in SOFTWARE_LIST
  #     you can do so using the following Markdown syntax:
  #           [IINA](//example.com)
  #     This will make sure the user is redirected to correct page, and that the
  #     potential semicolon (`:`) in URL prefixed "http(s)://" don't trigger the
  #     splitting parse errors.
  ######################################################################
  - name: "Full Library ✨"
    # list_title: "Full Library ✨"
    collapsible: true
    description:
      - "Reverse Engineering: IDA by Hex-Rays, Asset Catalog Tinkerer, Bit
        Slicer, CAARPlayer, Hopper Disassembler, imhex, iOS App Signer,
        MachOView, Samra, Schemes, Sloth, Suspicious Package, veles, BinDiff,
        WhatsYourSign, Bananafish's Dumper"
      - "Penetration Testing: Burp Suite Professional, Kali Linux"
      - "Electrical Engineering: Cuprum, DSView, Fritzing, KiCAD, Arduino IDE"
      - "Development: Visual Studio Code, XCode, Captain, DB Browser for SQLite,
        JetBrains GoLand, OrbStack, Postman, Snippets Library, SnippetsLab,
        Streaker, SwiftUI Recipes, GitHub Desktop, Postgres.app, ResponsivelyApp"
      - "Graphics & UI: ColorSet, Figma, Pika, Sketch, Allusion, BeeRef, Pastel,
        Shapr3D, Aquarelo, Sip"
      - "Writing & Editing: Anytype, Haystack Editor, Heynote, Microsoft Office,
        Nova, Tangent Notes, Zotero"
      - "Photos & Videos: ImageOptim, Redacted, IINA, VN"
      - "General & Messaging: NetNewsWire, Archiver, Expenses, TIDAL, Trust
        Wallet, VirtualBuddy, Slack, Signal, Stempel, Table Tool"
      - "Utilities: Amphetamine, [Accents](//mahdi.jp/apps/accents), Manila,
        ItsyCal, AltTab, CleanShot X, BoringNotch, Command X, Karabiner, Locker
        Widgets, Maccy, MacPass, MeetingBar, Pure Paste, Spaceman, Folder Peek,
        OneThing, Tiles, Image2Icon, Mission Control Plus, Table Plus, WiFi
        Explorer, Vanilla"
      - "File Transfer: Android File Transfer, Cyberduck, Rayon, Syncthing,
        Downie, Folx, Mounty"
      - "Extensions: **XCode** Comment Wrapper, Copilot for XCode,
        SwiftFormat<br /> **Safari** HighlightJSON, Hush, ImageFinder, Oldr,
        OneTab, Shiori, SingleFile, Wappalzyer, Wipr"
      - "Drivers: Logi Options+, Logitech G HUB, Brother Printer"

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
      - "HackerNews is a social news website that showcases user-submitted
        technology-related news and discussions. I use it daily to discover new
        tech-related releases and latest information."
  - name: "Lobste.rs"
    link: "https://lobste.rs/"
    description:
      - "Lobste.rs is a technology-focused link aggregator that curates and
        shares user-submitted stories and discussions about programming,
        technology, and related topics. Quite similar to previous, but requires
        user-invitation to be able to submit and comment. Mostly focused on
        FreeBSD and other `*BSD` distributions."
  - name: "Hackaday.com"
    link: "https://hackaday.com"
    description: 
      - "Hackaday serves up fresh hacks every day from around the Internet. It 
        mostly writes and publishes stories about Electronics, Electrical Engineering, 
        and Hacking creativity & thinkering, mostly specific to hardware."
# Add <as many other> [tools/section/subsection/list_title] here.
# ...

## Ref//
## @see: https://works-for-me.github.io/index.html (WFM/Original/Samples)
## @see: https://github.com/mykolaharmash/works-for-me (Original GitHub Inspiration Repo)
---
