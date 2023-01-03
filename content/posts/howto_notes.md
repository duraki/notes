---
title: "How to write Notes"
---

* Use Markdown for everything, stand-alone deployment
* Use shortcodes, and develop custom ones
	* Note: shortcodes are commented-out
	* Note: correct syntax is `{{`<..>`}}` (no spaces between `{}` & `<>`)
* Clear and consistent, easy to implement new features

### Including Images

To include images, copy the image to `/content/posts/images/*`. Then when you want to include it, use either of:

``` 
# => like this
![Image Caption](/posts/images/image-of-choice.png)

# => or
{{ < imgcap title="Image Caption" src="/posts/images/image-of-choice.png" > }}
```

The folder `images` in `content/posts` is created to index those files/images in the final build or deploy, and therefore removes the overhead of the Hugo processing. Some more [documentation](https://gohugo.io/content-management/image-processing/) on Hugo website.

### Including Files

To include files of any type, ready to be downloaded, copy the file to `/content/posts/files/*`. Then include it in your post as instructed below:

```
[File to Download](/posts/files/some_file_to_download-example.pdf)
```

The folder `/content/posts/files` is used to serve and index those files in the final build/deploy.

### Markdown

**Styled Blocks**

```
::: alert red
This is a **Red Alert!** Take cover.
:::
```

**Typical Insertions**

Use `>` to quote in markdown block

```
>  For I know the plans I have for you, declares the LORD, 
   plans to prosper you and not to harm you, plans to give 
   you hope and a future. 

   - Jeremiah 29:11
```

**Wikipedia Insertion**

*You can either use named parameters:*

```
{{ < wikipedia tag="VIC_cipher" > }}
{{ < wikipedia tag="VIC_cipher" lang="fr" > }}
{{ < wikipedia tag="VIC_cipher" lang="fr" title="" > }}
{{ < wikipedia tag="VIC_cipher" title="VIC Cipher" > }}
{{ < wikipedia tag="VIC_cipher" lang="en" title="VIC Cipher" > }}
```

**Inserting [FontAwesome](https://fontawesome.com/) Icons**

```
# => in markdown (md)
## Some of my photos :fa-camera-retro:
```

**Highlight lines in code**

[List of supported languages](https://gohugo.io/content-management/syntax-highlighting#list-of-chroma-highlighting-languages)

```
# => xml
{{ < highlight xml "linenos=table, linenostart=11, hl_lines=1 3"> }}
<category blog="posts">
    <label xml:lang="en" text="Article" />
</category>
{{ < /highlight > }}

# => go
{{ < highlight go "linenos=table,hl_lines=8 15-17,linenostart=199" > }}
// ... code
{{ < / highlight > }}

# => go - specific lines
go { linenos=table,hl_lines=[8,"15-17"],linenostart=199 }
// ... code
```

**Reference a link**

```
{{ < ref /blog > }}
```

### Shortcodes

**Caption images via this shortcode**

```
<span class="caption-wrapper">
  <img class="caption" src="/images/2016/thetheme/1.png" title="Sample caption" alt="Sample caption">
  <span class="caption-text">Sample caption</span>
</span>
```

```
{{ < imgcap title="Sample caption" src="/images/2016/thetheme/1.png" > }}
```

**Insert Gist or GitHub Repository**

```
{{ < gist duraki 78985452 > }}

  # ... or ...

{{ < github repo="duraki/notes" file="/path/to/file" lang="language" options="highlight-options" >}}
```

**Insert Instagram Image**

```
# => https://www.instagram.com/p/BWNjjyYFxVx/

# => Normal Instagram view
{{ < instagram BWNjjyYFxVx > }}

# => Hide caption
{{ < instagram BWNjjyYFxVx hidecaption > }}
```

**Insert a Tweet in post**

```
# => https://twitter.com/SanDiegoZoo/status/1453110110599868418

{{ < tweet user="SanDiegoZoo" id="1453110110599868418" > }}
```

**Hide Something**

```
{{ < details > }}
This website is provided for free educational purposes. Knowledge shared here can be used for personal gain and experience.
{{ < /details > }}

{{ < details "Read More" > }}
Note: Some <read more> note for further details, or hidden image/text/component.
{{ < /details > }}
```

[More shortcodes](https://gohugo.io/content-management/shortcodes/) on official website.

### Deploy

Check details of `README.md` to learn how to deploy **~notes** on local and remote machines.

