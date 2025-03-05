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

if (
  (window.location.href.indexOf('//localhost') > 0) ||
  (window.location.href.indexOf('//127.0.0.1') > 0) ||
  (window.location.href.indexOf('//0.0.0.0') > 0)
) {
  /* do not no-op console.* funcs in dev env */
} else {
  /* no-op console.* funcs in prod env */
  console.log = function () { };
  console.debug = function () { };
  console.error = function () { };
  console.info = function () { };
  console.warn = function () { };
  DEV_MODE = false;
}

console.log("Uses DEV_MODE=" + DEV_MODE + " environment ...");

// Track navigated pages
let pages = [window.location.pathname];
let basedir_rx = new RegExp(pages, 'g');
console.log("Pages Array (Directory Pathnames)=", pages)
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
    href = href.trimLeft(1); // Fix relative path
  }

  href = URI(href);
  let uri = URI(window.location);

  pages.push(href.path());
  uri.setQuery("stackedNotes", pages.slice(1, pages.length));

  let old_pages = pages.slice(0, level - 1);
  let state = { pages: old_pages, level: level };

  window.history.pushState(state, "", uri.href());
  console.log("Browser History updated with state:", state);
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
}

/**
 * Updates the status of links based on stacked notes.
 */
function updateLinkStatuses() {
  console.log("Updating link statuses ...");

  links = Array.prototype.slice.call(document.querySelectorAll("a"));
  console.log("All collected links ready for the update:", links);

  links.forEach(function(e) {
    if (pages.indexOf(e.getAttribute("href")) > -1) {
      e.classList.add("active");
    } else {
      e.classList.remove("active");
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

  let container = document.querySelector(".grid");

  let fragment = document.createElement("template");
  fragment.innerHTML = text;

  let element = fragment.content.querySelector(".page");
  container.appendChild(element);

  stackNote(href, level);

  setTimeout(
    function(element, level) {
      element.dataset.level = level + 1;
      initializePage(element, level + 1);
      element.scrollIntoView();

      if (window.MathJax) {
        window.MathJax.typeset();
      }
    }.bind(null, element, level),
    10
  );
}

/**
 * Fetches a note via AJAX and inserts it into the stack at the given
 * level.
 * @param {string} href - The note URL.
 * @param {number} level - The note hierarchy stack level.
 * @returns 
 */
function fetchNote(href, level) {
  console.log("Fetching note:", href);

  if (pages.indexOf(href) > -1) return;
  level = Number(level) || pages.length;

  const request = new Request(href);
  fetch(request)
    .then((response) => response.text())
    .then((text) => {
      insertNote(href, text, level);
    });
}

/**
 * Initializes interactivity for a given page.
 * @param {HTMLElement} page - The page element to initialize.
 * @param {number} level - The stack level.
 */
function initializePage(page, level) {
  console.log("Initializing page at level:", level);

  level = level || pages.length;
  links = Array.prototype.slice.call(page.querySelectorAll("a"));

  links.forEach(async function(element) {
    var rawHref = element.getAttribute("href");
    element.dataset.level = level;

    if (rawHref && !(
      // Skip if rawHref is remote
      (
        rawHref.indexOf("http://") === 0 ||
        rawHref.indexOf("https://") === 0 ||
        rawHref.indexOf("#") === 0 ||
        rawHref.includes(".pdf") ||
        rawHref.includes(".svg")
      )
    )) {

      const regex_matches_basedir_level = basedir_rx;
      if (element.href.search(regex_matches_basedir_level) != "-1") {
        // rawHref starts with correct notation.
      } else {
        origUrl = URI(element.href).origin();
        origPath = URI(element.href).path();
        element.href = origUrl + "/notes" + origPath;
      }
    }

    if (rawHref && !(
        // Internal Links Only
        (
          rawHref.indexOf("http://") === 0 ||
          rawHref.indexOf("https://") === 0 ||
          rawHref.indexOf("#") === 0 ||
          rawHref.includes(".pdf") ||
          rawHref.includes(".svg")
        )
    )) {
      
      var prefetchLink = element.href;

      async function myFetch() {
        let response = await fetch(prefetchLink);
        let text = await response.text();
        let ct = await response.headers.get("content-type");

        if (ct.includes("text/html")) {
          // Click to open
          element.addEventListener("click", function(e) {
            if (!e.ctrlKey && !e.metaKey) {
              e.preventDefault();
              insertNote(element.getAttribute("href"), text, this.dataset.level);
              hidePreview();
            }
          });

          // Hover to see preview
          element.addEventListener("mouseenter", function(e) {
            showPreview(text, element);
          });
          element.addEventListener("mouseleave", function(e) {
            hidePreview();
          });
        }
        updateLinkStatuses();
      }
      return myFetch();
    }
  });
}

/* Setup global preview container */
const previewContainer1 = document.createElement('div');
previewContainer1.classList.add('preview-container');

const previewContainer2 = document.createElement('div');
previewContainer1.appendChild(previewContainer2)
previewContainer2.classList.add('preview-container-2')

const previewContainerArrow = document.createElement('div');
previewContainerArrow.classList.add('preview-container-arrow');
previewContainer1.appendChild(previewContainerArrow);

const previewContainer3 = document.createElement('div');
previewContainer2.appendChild(previewContainer3)
previewContainer3.classList.add('preview-container-3')

const previewContainer4 = document.createElement('div');
previewContainer3.appendChild(previewContainer4)
previewContainer4.classList.add('preview-container-4')
document.getElementsByTagName('body')[0].appendChild(previewContainer1);

/**
 * Show preview of a linked note on mouse hover. Position content anchor
 * to the given element. 
 * @param {string} previewHtml - HTML content of the preview.
 * @param {HTMLElement} anchorElement - The link triggering the preview.
 */
function showPreview(previewHtml, anchorElement) {
  let fragment = document.createElement("template");
  fragment.innerHTML = previewHtml;

  let element = fragment.content.querySelector(".page");
  previewContainer4.appendChild(element);

  const previewContainer1Style = getComputedStyle(previewContainer1);
  const previewContainer3Style = getComputedStyle(previewContainer3);
  const previewContainer4Style = getComputedStyle(previewContainer4);

  // Read css properties
  const previewContainerWidth = parseInt(previewContainer1Style.getPropertyValue('--preview-width'), 10);
  const previewContainerHeight = parseInt(previewContainer1Style.getPropertyValue('--preview-max-height'), 10);
  const marginLeft = parseFloat(previewContainer3Style.getPropertyValue('margin-left'), 10);
  const marginTop = parseFloat(previewContainer3Style.getPropertyValue('margin-top'), 10);
  const scale = parseFloat(previewContainer4Style.getPropertyValue('--preview-scale'));
  const arrowBaseWidth = parseInt(previewContainer4Style.getPropertyValue('--arrowBaseWidth'), 10);
  const arrowLength = parseInt(previewContainer4Style.getPropertyValue('--arrowLength'), 10);

  const { x, y, direction, arrowTop } = calculatePreviewElementPosition(previewContainerWidth, previewContainerHeight, marginLeft, marginTop, scale, arrowBaseWidth, arrowLength, anchorElement);
  previewContainer1.style['transform'] = `translate3d(${x}px, ${y}px, 0)`;
  previewContainerArrow.classList.remove('left', 'right');
  previewContainerArrow.classList.add(direction);
  previewContainerArrow.style['top'] = `${arrowTop}px`;

  previewContainer1.classList.add('active');
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
function calculatePreviewElementPosition(width, height, marginLeft, marginTop, scale, arrowBaseWidth, arrowLength, anchorElement) {

  const previewContainerWidth = (width + (marginLeft / scale)) * scale;
  const previewContainerHeight = (height + (marginTop / scale));
  const heightOffset = -50;

  const { innerWidth: windowWidth, innerHeight: windowHeight } = window;

  const { x: anchorX, y: anchorY, width: anchorWidth, height: anchorHeight } = anchorElement.getBoundingClientRect();

  // Initial positions
  let previewContainerX = 0;
  let previewContainerY = Math.min(windowHeight - previewContainerHeight, anchorY + heightOffset);
  let direction = 'left';
  let arrowTop = anchorY - previewContainerY - arrowBaseWidth + (anchorHeight / 2);

  // Horizontal
  if (anchorX < window.innerWidth / 2) {
    // Left side link, show preview to the right
    previewContainerX = Math.min(windowWidth - previewContainerWidth, anchorX + anchorWidth);
    direction = 'right';
  } else {
    // Right side link, show preview to the left
    previewContainerX = Math.max(0, anchorX - previewContainerWidth - (arrowLength / 2));
    direction = 'left';
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
  previewContainer1.classList.remove('active');
  Array.from(previewContainer4.children).map(e => previewContainer4.removeChild(e));
}

// Handle browser navigation (Back/Forward buttons)
window.addEventListener("popstate", event => {
  console.warn("Handling popstate event:", event);
  // TODO: check state and pop pages if possible, rather than reloading.
  window.location = window.location; // this reloads the page.
});

// On page load, initialize first page and fetch stacked notes
window.onload = function() {
  initializePage(document.querySelector(".page"), 1);

  let stacks = [];
  uri = URI(window.location);
  if (uri.hasQuery("stackedNotes")) {
    stacks = uri.query(true).stackedNotes;
    if (!Array.isArray(stacks)) {
      stacks = [stacks];
    }
    for (let i = 0; i < stacks.length; i++) {
      fetchNote(stacks[i], i + 1);
    }
  }
};
