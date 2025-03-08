/**
 * This Javascript code manages a note-stacking system, allowing users to dynamically
 * load and navigate through different pages (ie. notes) within a grid-like structure.
 * The loading of the notes content is AJAX-based, alongside the navigation history,
 * and interactive previews.
 *
 * This Javascript code enables features such as:
 *    - Dynamically fetching and inserting _note_ content
 *    - Maintaining a history stack of _notes_ via the Browser's history API
 *    - Handling link statuses and interactions of the _notes_
 *    - Displaying previews of linked content (_notes_) in preview pop-ups
 */
console.log("Initializing note stacking script ...");
var DEV_MODE = true;

const ALIGN_LEFT_PX_SIZE = 40; // 40px
var AlignLeftMathCalc = 40; // calc = eq + ALIGN_LEFT_PX_SIZE

const NOTE_WIDTH_DEFAULT = 625; // width: 625px (default width of each note)
var InitialNoteCoolumnsContainerWidth = NOTE_WIDTH_DEFAULT; // width: 625px (stores total width of all notes + available space)

if (
  window.location.href.includes("//localhost") ||
  window.location.href.includes("//127.0.0.1") ||
  window.location.href.includes("//0.0.0.0")
) {
  // do not no-op console.* funcs in dev env
} else {
  // no-op console.* funcs in prod env
  console.log = console.debug = console.error = console.info = console.warn = () => {};
  DEV_MODE = false;
}

console.log("Uses DEV_MODE=" + DEV_MODE + " environment ...");

// Track navigated pages
let pages = [window.location.pathname];
let basedir_rx = new RegExp(pages, "g");
console.log("Pages Array (Directory Pathnames)=", pages);
console.log("Matching Regex Pattern (Base Dir. Path)=", basedir_rx);

// UI Configurations
let switchDirectionWindowWidth = 900;
let animationLength = 200;

/**
 * Adds a note to the stack and updates browser history.
 * @param {string} href - The URL of the note to stack.
 * @param {number} level - The depth level of the note in the stack.
 */
function stackNote(href, level) {
  level = Number(level) || pages.length;
  if (level == 1) level = 2;

  console.log("Stacking note at level:", level);

  if (href.startsWith("../")) {
    href = href.slice(1); // Fix relative path
  }

  href = URI(href);
  const uri = URI(window.location);

  pages.push(href.path());
  uri.setQuery("stackedNotes", pages.slice(1));

  let old_pages = pages.slice(0, level - 1);
  let state = { pages: old_pages, level };

  window.history.pushState(state, "", uri.href());
  console.log("Browser History updated with state:", state);
  
  // Force visibility check after note insertion
  requestAnimationFrame(() => {
    onScrollCheck();
    // Force a second check to ensure proper rendering
    requestAnimationFrame(onScrollCheck);
  });
}

/**
 * Removes notes beyond a certain stack level.
 * @param {number} level - The level to retain up to.
 */
function unstackNotes(level) {
  console.log("Unstacking note from level:", level);

  let container = document.querySelector(".grid");
  let children = Array.from(container.children);

  for (let i = level; i < children.length; i++) {
    container.removeChild(children[i]);
  }
  pages = pages.slice(0, level);

  // onScrollCheck();
}

/**
 * Updates the status of links based on stacked notes.
 */
function updateLinkStatuses() {
  const links = Array.from(document.querySelectorAll("a"));

  links.forEach(function (link) {
    if (pages.indexOf(link.getAttribute("href")) > -1) {
      link.classList.add("active");
    } else {
      link.classList.remove("active");
    }
  });
}

/**
 * Inserts a fetched note into the document at a specific stack level.
 * The function first removes any notes up to that level and then cont.
 * inserting a new note at the given level.
 * @param {string} href - The note URL.
 * @param {string} text - The HTML content of the note.
 * @param {number} level - The note hierarchy stack level.
 */
function insertNote(href, text, level) {
  level = Number(level) || pages.length;
  unstackNotes(level);

  const container = document.querySelector(".grid");
  container.classList.add("NoteColumnsContainer");

  const fragment = document.createElement("template");
  fragment.innerHTML = text;
  const element = fragment.content.querySelector(".page");
  element.classList.add("NoteContainer");

  // Calculate the padding to the left for vertical note title
  const newAlignStyle = `left: ${AlignLeftMathCalc}px; right: -585px`;
  element.style = newAlignStyle;
  AlignLeftMathCalc += ALIGN_LEFT_PX_SIZE; // Update AlignLeft calc. result in global var

  // Calculate initial root container width
  const elInitialRootNote = document.querySelector(".InitialRootNote");
  InitialNoteCoolumnsContainerWidth += 625; // 625px (width of each note) in global var 
  elInitialRootNote.style.width = `${InitialNoteCoolumnsContainerWidth}px`;

  container.appendChild(element);
  stackNote(href, level);

  handleExternalLinks();

  setTimeout(() => {
    refreshNoteOverlayShadowMask(); // Set "Overlay" class to previous note
    element.dataset.level = level + 1;
    initializePage(element, level + 1);

    // Improved smooth scrolling without jitter
    const scrollContainer = document.querySelector(".NoteColumnsScrollingContainer");
    const finalScrollPosition = scrollContainer.scrollWidth - scrollContainer.clientWidth;

    // Use native smooth scrolling
    scrollContainer.scrollTo({
      left: finalScrollPosition + 10,
      behavior: 'instant'
    });

    // Only use as fallback if needed
    element.scrollIntoView({
      inline: "end",
      block: "end",
      behavior: "smooth"
    });


    // // Improved smooth scrolling without jitter
    // const scrollContainer = document.querySelector(".NoteColumnsContainer");
    // const finalScrollPosition = scrollContainer.scrollWidth - scrollContainer.clientWidth;
    // console.log("finalScrollPosition=", finalScrollPosition);

    
    // // Use native smooth scrolling
    // scrollContainer.scrollTo({
    //   left: finalScrollPosition,
    //   behavior: 'smooth'
    // });
    
    // // Only use as fallback if needed
    // element.scrollIntoView({
    //   inline: "end",
    //   // block: "end",
    //   behavior: "smooth"
    // });
      
    onScrollCheck();

    if (window.MathJax) window.MathJax.typeset();
  }, 10);
}

function refreshNoteOverlayShadowMask() {
  let allNoteContainers = document.querySelectorAll(".page.NoteContainer");

  if (allNoteContainers.length <= 2) {
    // skip shadow mask if only two notes are shown (incl. RootNote)
    return;
  }

  if (allNoteContainers.length >= 3) {
    let noteArray = Array.from(allNoteContainers);

    noteArray.forEach((noteContainer) => {
      // apply shadow mask to all notes
      noteContainer.classList.add("Overlay");
    });

    // onScrollCheck();
  }
}

// Function to show the obscured label and hide the page title
function showObscuredHidePageTitle(note) {
  note.querySelectorAll(".ObscuredLabel").forEach((el) => (el.style.display = "block"));
  // note.querySelectorAll(".content-page-header-title").forEach((el) => (el.style.display = "none"));
}

// Function to hide the obscured label and show the page title
function hideObscuredShowPageTitle(note) {
  note.querySelectorAll(".ObscuredLabel").forEach((el) => (el.style.display = "none"));
  note.querySelectorAll(".content-page-header-title").forEach((el) => (el.style.display = "block"));
}

/**
 * Fetches a note via AJAX and inserts it into the stack at the given
 * level.
 * @param {string} href - The note URL.
 * @param {number} level - The note hierarchy stack level.
 */
function fetchNote(href, level) {
  if (pages.includes(href)) return;
  level = Number(level) || pages.length;

  fetch(href)
    .then((response) => response.text())
    .then((text) => {
      insertNote(href, text, level);
      onScrollCheck();
    });
}

/**
 * Initializes interactivity for a given page.
 * @param {HTMLElement} page - The page element to initialize.
 * @param {number} level - The stack level.
 */
function initializePage(page, level) {
  console.log("Initializing page at level:", level);

  if (level === 1) {
    page.classList.add("NoteContainer");
    page.style = "left: 0px; right: -585px";
  }

  level = level || pages.length;
  const links = Array.from(page.querySelectorAll("a"));

  links.forEach(async (element) => {
    // Add note stacking event handler pause flag to all links
    element.addEventListener("mouseenter", () => {
      window.pauseNoteStacking = true;
    });
    // see 'stackedNotesHandler.js' for more details
    element.addEventListener("mouseleave", () => {
      window.pauseNoteStacking = false;
      // Force a check after mouse leaves
      requestAnimationFrame(() => {
        onScrollCheck();
      });
    });


    const rawHref = element.getAttribute("href");
    element.dataset.level = level;

    if (
      rawHref &&
      !(
        rawHref.startsWith("http://") ||
        rawHref.startsWith("https://") ||
        rawHref.startsWith("#") ||
        rawHref.includes(".pdf") ||
        rawHref.includes(".svg")
      )
    ) {
      const regex_matches_basedir_level = basedir_rx;
      if (element.href.search(regex_matches_basedir_level) === -1) {
        const origUrl = URI(element.href).origin();
        const origPath = URI(element.href).path();
        element.href = `${origUrl}/notes${origPath}`;
      }
    }

    if (
      rawHref &&
      !(
        rawHref.startsWith("http://") ||
        rawHref.startsWith("https://") ||
        rawHref.startsWith("#") ||
        rawHref.includes(".pdf") ||
        rawHref.includes(".svg")
      )
    ) {
      const prefetchLink = element.href;

      async function myFetch() {
        const response = await fetch(prefetchLink);
        const text = await response.text();
        const ct = await response.headers.get("content-type");

        if (ct.includes("text/html")) {
          // Click to open
          element.addEventListener("click", function(e) {
            if (!e.ctrlKey && !e.metaKey) {
              e.preventDefault();
              insertNote(element.getAttribute("href"), text, this.dataset.level);
              // hidePreview();
            }
          });

          // Hover to see preview
          element.addEventListener("mouseenter", () => {
            showPreview(text, element);
          });
          element.addEventListener("mouseleave", hidePreview);
        }
        updateLinkStatuses();
      }
      await myFetch();
    }
  });
  handleExternalLinks();
  
  onScrollCheck();
}

/* Setup global preview container */
const previewContainer1 = document.createElement("div");
previewContainer1.classList.add("preview-container");

const previewContainer2 = document.createElement("div");
previewContainer1.appendChild(previewContainer2);
previewContainer2.classList.add("preview-container-2");

const previewContainerArrow = document.createElement("div");
previewContainerArrow.classList.add("preview-container-arrow");
previewContainer1.appendChild(previewContainerArrow);

const previewContainer3 = document.createElement("div");
previewContainer2.appendChild(previewContainer3);
previewContainer3.classList.add("preview-container-3");

const previewContainer4 = document.createElement("div");
previewContainer3.appendChild(previewContainer4);
previewContainer4.classList.add("preview-container-4");
document.body.appendChild(previewContainer1);

/**
 * Show preview of a linked note on mouse hover. Position content anchor
 * to the given element.
 * @param {string} previewHtml - HTML content of the preview.
 * @param {HTMLElement} anchorElement - The link triggering the preview.
 */
function showPreview(previewHtml, anchorElement) {
  const fragment = document.createElement("template");
  fragment.innerHTML = previewHtml;

  const element = fragment.content.querySelector(".page");
  previewContainer4.appendChild(element);

  const previewContainer1Style = getComputedStyle(previewContainer1);
  const previewContainer3Style = getComputedStyle(previewContainer3);
  const previewContainer4Style = getComputedStyle(previewContainer4);

  // Read css properties
  const previewContainerWidth = parseInt(previewContainer1Style.getPropertyValue("--preview-width"), 10);
  const previewContainerHeight = parseInt(previewContainer1Style.getPropertyValue("--preview-max-height"), 10);
  const marginLeft = parseFloat(previewContainer3Style.getPropertyValue("margin-left"), 10);
  const marginTop = parseFloat(previewContainer3Style.getPropertyValue("margin-top"), 10);
  const scale = parseFloat(previewContainer4Style.getPropertyValue("--preview-scale"));
  const arrowBaseWidth = parseInt(previewContainer4Style.getPropertyValue("--arrowBaseWidth"), 10);
  const arrowLength = parseInt(previewContainer4Style.getPropertyValue("--arrowLength"), 10);

  const { x, y, direction, arrowTop } = calculatePreviewElementPosition(
    previewContainerWidth,
    previewContainerHeight,
    marginLeft,
    marginTop,
    scale,
    arrowBaseWidth,
    arrowLength,
    anchorElement
  );
  previewContainer1.style.transform = `translate3d(${x}px, ${y}px, 0)`;
  previewContainerArrow.classList.remove("left", "right");
  previewContainerArrow.classList.add(direction);
  previewContainerArrow.style.top = `${arrowTop}px`;

  previewContainer1.classList.add("active");
}

/**
 * @param {number} width
 * @param {number} height
 * @param {number} marginLeft
 * @param {number} marginTop
 * @param {number} scale
 * @param {number} arrowBaseWidth
 * @param {number} arrowLength
 * @param {HTMLElement} anchorElement
 */
function calculatePreviewElementPosition(
  width,
  height,
  marginLeft,
  marginTop,
  scale,
  arrowBaseWidth,
  arrowLength,
  anchorElement
) {
  const previewContainerWidth = (width + marginLeft / scale) * scale;
  const previewContainerHeight = height + marginTop / scale;
  const heightOffset = -50;

  const { innerWidth: windowWidth, innerHeight: windowHeight } = window;

  const {
    x: anchorX,
    y: anchorY,
    width: anchorWidth,
    height: anchorHeight
  } = anchorElement.getBoundingClientRect();

  // Initial positions
  let previewContainerX = 0;
  let previewContainerY = Math.min(
    windowHeight - previewContainerHeight,
    anchorY + heightOffset
  );
  let direction = "left";
  let arrowTop = anchorY - previewContainerY - arrowBaseWidth + anchorHeight / 2;

  // Horizontal
  if (anchorX < window.innerWidth / 2) {
    // Left side link, show preview to the right
    previewContainerX = Math.min(
      windowWidth - previewContainerWidth,
      anchorX + anchorWidth
    );
    direction = "right";
  } else {
    // Right side link, show preview to the left
    previewContainerX = Math.max(
      0,
      anchorX - previewContainerWidth - arrowLength / 2
    );
    direction = "left";
  }

  return {
    x: previewContainerX,
    y: previewContainerY,
    direction,
    arrowTop
  };
}

/**
 * Hide the preview container.
 */
function hidePreview() {
  previewContainer1.classList.remove("active");
  Array.from(previewContainer4.children).forEach((e) => previewContainer4.removeChild(e));
}

/** =START Sonnet 3.5 Solution */

// Function to check if element is visible in viewport with threshold
function isVisibleInViewport(element, threshold = 40) {
  const rect = element.getBoundingClientRect();
  const scrollContainer = document.querySelector(".NoteColumnsScrollingContainer");
  const containerRect = scrollContainer.getBoundingClientRect();
  
  // Calculate what percentage of the element is visible
  const visibleWidth = Math.min(rect.right, containerRect.right) - Math.max(rect.left, containerRect.left);
  const percentVisible = (visibleWidth / rect.width) * 100;
  
  // Get all notes for z-index comparison
  const notes = Array.from(document.querySelectorAll(".page.NoteContainer"));
  const currentIndex = notes.indexOf(element);
  
  // Check if note is overlapped by notes with higher z-index
  const isOverlapped = notes.some((otherNote, index) => {
    if (otherNote === element || index <= currentIndex) return false;
    const otherRect = otherNote.getBoundingClientRect();
    return (rect.left < otherRect.right && rect.right > otherRect.left);
  });
  
  return percentVisible >= threshold && !isOverlapped;
}

function getTotalObscuredLabelWidth() {
  const obscuredLabels = document.querySelectorAll('.ObscuredLabel[style*="display: block"]');
  return Array.from(obscuredLabels).reduce((total, label) => {
    const width = label.getBoundingClientRect().width;
    return total + width;
  }, 0);
}

// Function to check visibility on horizontal scroll and show/hide obscured labels
// The visibility thresholds are:
// - 30% for root note
// - 40% for middle notes
// - 50% for last note
function onScrollCheck() {
  // Pause flag check on global vars defined in stackedNoteHandler.js which is used
  // to track hover state and return early if hovering over backlinks
  if (window.pauseNoteStacking) return;

  browserWindowWidth = window.innerWidth; // get browser window width in pixels

  // Subtract the width of visible ObscuredLabels from the browser window width
  const totalObscuredWidth = getTotalObscuredLabelWidth();
  const adjustedWindowWidth = browserWindowWidth - totalObscuredWidth;
  // Calculate number of notes that can fit in the adjusted browser window width
  numberOfNotesThatCanFit = Math.floor(adjustedWindowWidth / 625);

  const notes = document.querySelectorAll(".page.NoteContainer");
  const notesArray = Array.from(notes);


  if (notesArray.length <= numberOfNotesThatCanFit + 1) {
    // if the number of notes that can fit in the browser window is greater than or equal to the number of notes in the array
    // then handle notes as stacked notes
    handleStackedNotes(notes, notesArray);
  } else {
    // otherwise, handle notes as  wide notes
    handleStackedNotesWide(notes, notesArray);
  }

  animationFrame(notesArray);

  return;
}

// Function to check viewport on window resize
function onWindowResize() {
  onScrollCheck();
}

// Update event listeners
window.addEventListener('resize', onWindowResize);
window.addEventListener('scroll', onWindowResize);
window.addEventListener('scrollend', onWindowResize);

document.querySelector(".NoteColumnsScrollingContainer").addEventListener("scrollend", function() {
  const container = this;
  // requestAnimationFrame(() => {
    onScrollCheck();
  // });
});

document.querySelector(".NotePageRoot").addEventListener("scroll", function () {
  const container = this;
  // requestAnimationFrame(() => {
    onScrollCheck();
  // });
});

// onScrollCheck();
/** =END of Sonnet 3.5 Solution */

// Handle browser navigation (Back/Forward buttons)
window.addEventListener("popstate", (event) => {
  console.warn("Handling popstate event:", event);
  if (window.location.pathname.includes("stackedNotes")) {
    // TODO: check state and pop pages if possible, rather than reloading.
    window.location.reload();
  }
});

// Run on page load to check initial visibility
window.onload = function () {
  initializePage(document.querySelector(".page"), 1);

  const elInitialRootNote = document.querySelector(".InitialRootNote");
  if (elInitialRootNote) {
    elInitialRootNote.style.width = `${InitialNoteCoolumnsContainerWidth}px`;
  }

  const uri = URI(window.location);
  if (uri.hasQuery("stackedNotes")) {
    let stacks = uri.query(true).stackedNotes;
    if (!Array.isArray(stacks)) {
      stacks = [stacks];
    }
    stacks.forEach((stack, i) => {
      fetchNote(stack, i + 1);
      onScrollCheck();
    });
  }

};

// Global link handler for any dynamically added links in the document
// Used to track and handle note stacking and navigation mechanisms when 
// paused or resumed.
document.addEventListener('DOMContentLoaded', () => {
  const addPauseBehavior = (mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeName === 'A') {
          node.addEventListener('mouseenter', () => {
            window.pauseNoteStacking = true;
          });

          node.addEventListener('mouseleave', () => {
            window.pauseNoteStacking = false;
            requestAnimationFrame(() => {
              onScrollCheck();
            });
          });
        }
      });
    });
  };

  const observer = new MutationObserver(addPauseBehavior);
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
})