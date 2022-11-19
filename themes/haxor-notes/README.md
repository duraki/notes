# haxor-notes 

A [Hugo](https://gohugo.io/) theme optimized for publishing my personal [notes](http://notes.durakiconsulting.com).

It is hard fork from [Justin's](https://justindsmith.me) theme, which is a fork of [Cortex theme](https://github.com/jethrokuan/cortex), with a number of enhancements to more closely mimic [Andy Matuschak's notes](https://notes.andymatuschak.org). Some extra features has been added by [me](https://twitter.com/0xduraki) such is [engine debug mode](./layouts/partials/debugprint.html), [debug shortcode](./layouts/shortcodes/debug.html), and [console_log](./layouts/partials/console_log.html). This fork is also matching UI style to that of my [blog](https://duraki.github.io). I've also implemented [stacked mode](./layouts/partials/debugprint.html) for top-level index and fixed [backlinks](./layouts/partials/backlinks.html) bug.

Example Site: [duraki notes](http://notes.durakiconsulting/)

![Screenshot](./screenshot.png)

Features:

- Opens new pages in an ever-growing list to maintain context of how you arrived at a page.
- This fork also fixes the top-level index page. It handles index page as it was subcontexed stacked note. 
- Tracks and displays "backlinks" between pages to allow for related concept exploration.
- This fork also fixes backlinks between stacked notes, which sometimes yielded markdown raw data. 
- Shows preview of content on link hover to get a peek at the content before opening.
- Customizable look-and-feel via to match style of my blog.
- Text search to find interesting starting points into the knowledge graph.

## Search

In order for search to work, you must have a `/content/search/_index.md` file, so that `/search` is a valid url.

## Custom Styling

The default theme style matches [my blog](http://notes.durakiconsulting.com). You can configure the look and feel of the site using the `[params.styles]` property in your [`config.toml`](https://github.com/duraki/notes/themes/haxor-notes/blob/master/config.toml).

Here is a basic dark theme that can be tweaked:

```toml
[params.styles]
  # Base styles for entire site
  color = "#fff"
  backgroundColor = "#000"
  lineHeight = "1.6"
  fontFamily = "Arial, sans-serif"

  # Styles for header
  headerBackgroundColor = "#111"
  headerBorderBottomColor = "#666"
  headerColor = "#fafafa"

  # Styles for pages
  pageBackgroundColor = "#000"
  pageBorderLeftColor = "#333"
  pageLinkColor = "#10B981"
  pageMaxWidth = "625px"
  pageFontSize = "16px"
  pageLineHeight = "22px"

  # Styles for the "backlink" section at the bottom of each page
  backlinksBackgroundColor = "#222"
  backlinksBorderRadius = "3px"
  backlinkLabelColor = "#aaa"
  backlinkTitleColor = "#ccc"
  backlinkPreviewColor = "#eee"
  backlinkHoverBackgroundColor = "#444"

  # Styles for the preview hover popup
  previewWidth = "500px"
  previewMaxHeight = "350px"
  previewScale = "0.7"
  previewBoxShadowTopColor = "rgba(255, 255, 255, 0.08)"
  previewBoxShadowRightColor = "rgba(255, 255, 255, 0.04)"
  previewBoxShadowBottomColor = "rgba(255, 255, 255, 0.15)"
  previewBoxShadowLeftColor = "rgba(255, 255, 255, 0.04)"

  # Styles for the search page
  searchExtractColor = "#666"
```
