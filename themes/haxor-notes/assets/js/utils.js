// Define the handler function
function handleExternalLinks() {
  document.querySelectorAll('a[href]').forEach(link => {
    // Skip if already processed
    if (link.dataset.processed) return;
    
    const isInternal = (
      link.href.startsWith('javascript:') ||
      (link.href.startsWith('/') && !link.href.startsWith('//')) ||
      link.href.includes('//deviltux.thedev.id') ||
      link.href.includes('//notes.durakiconsulting.com') ||
      link.href.includes('//localhost') ||
      link.href.includes('//127.0.0.1') ||
      link.href.includes('//0.0.0.0') ||
      link.href.includes('//duraki.github.io') ||
      link.href.startsWith('#')
    );

    if (!isInternal && !link.hasAttribute('target')) {
      link.setAttribute('target', '_blank');
      link.setAttribute('rel', 'noopener noreferrer');
    }
    
    // Mark as processed to avoid duplicate handlers
    link.dataset.processed = 'true';
  });
}

// Initial setup on DOM load
document.addEventListener('DOMContentLoaded', () => {
  console.warn("Setting up external links handler");
  handleExternalLinks();
});

// Function to get the view percentage width of an element
function getViewPercentageWidth(element) {
  const rect = element.getBoundingClientRect();
  const windowWidth = window.innerWidth || document.documentElement.clientWidth;
  const elementWidth = rect.width;

  // Calculate the percentage of the element's width that is visible in the viewport
  const visibleWidth = Math.max(0, Math.min(rect.right, windowWidth) - Math.max(rect.left, 0));
  return (visibleWidth / elementWidth) * 100;
}

function getViewPercentageWidthAsync(element) {
  pageRootXOffset = window.pageXOffset;
  const viewport = {
    left: window.pageXOffset,
    right: window.pageXOffset + window.innerWidth,
  };

  const elementBoundingRect = element.getBoundingClientRect();
  const elementPos = {
    left: elementBoundingRect.x + window.pageXOffset,
    right:
      elementBoundingRect.x + elementBoundingRect.width + window.pageXOffset,
  };

  if (viewport.left > elementPos.right || viewport.right < elementPos.left) {
    return 0;
  }

  // Element is fully within viewport
  if (viewport.left < elementPos.left && viewport.right > elementPos.right) {
    return 100;
  }

  // Element is bigger than the viewport
  if (elementPos.left < viewport.left && elementPos.right > viewport.right) {
    return 100;
  }

  const elementWidth = elementBoundingRect.width;
  let elementWidthInView = elementWidth;

  if (elementPos.left < viewport.left) {
    elementWidthInView = elementWidth - (window.pageXOffset - elementPos.left);
  }

  if (elementPos.right > viewport.right) {
    elementWidthInView =
      elementWidthInView - (elementPos.right - viewport.right);
  }

  const percentageInView = (elementWidthInView / window.innerWidth) * 100;

  return Math.round(percentageInView);
}

function removeElementsByClass(className) {
  const elements = document.getElementsByClassName(className);
  while (elements.length > 0) {
    elements[0].parentNode.removeChild(elements[0]);
  }
}

function elementsOverlap(el1, el2) {
  const domRect1 = el1.getBoundingClientRect();
  const domRect2 = el2.getBoundingClientRect();

  return !(
    domRect1.top > domRect2.bottom ||
    domRect1.right < domRect2.left ||
    domRect1.bottom < domRect2.top ||
    domRect1.left > domRect2.right
  );
}

function getBrowserWidthSize() {
  if (self.innerWidth) {
    return self.innerWidth;
  } else if (
    document.documentElement &&
    document.documentElement.clientHeight
  ) {
    return document.documentElement.clientWidth;
  } else if (document.body) {
    return document.body.clientWidth;
  }
  return 0;
}
