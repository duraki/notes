// Defn. pause flags which are used to prevent the handler from running when the user 
// is interacting with the note backlinks or the note itself (@see. 'backlinks.html')
let pauseNoteStacking = false;
window.pauseNoteStacking = false;

// Handling for 3 or fewer notes
function handleStackedNotes(notes, notesArray) {
    if (window.pauseNoteStacking) return;

    console.log('handleStackedNotes');
    notesArray.forEach(note => hideObscuredShowPageTitle(note));
    animationFrame(notesArray);
}

// Handling for more than 3 notes
function handleStackedNotesWide(notes, notesArray) {
    if (window.pauseNoteStacking) return;

    console.log('handleStackedNotesWide');
    
    const scrollContainer = document.querySelector(".NoteColumnsScrollingContainer");
    const containerRect = scrollContainer.getBoundingClientRect();

    notesArray.forEach((note, index) => {
        const rect = note.getBoundingClientRect();
        const isFirstNote = index === 0;
        const isLastNote = index === notesArray.length - 1;
        
        // Handling for first (root) note
        if (isFirstNote) {
            const rootNoteVisible = isVisibleInViewport(note, 30) &&
                rect.left >= containerRect.left;
        
            if (rootNoteVisible) {
                hideObscuredShowPageTitle(note);
            } else {
                showObscuredHidePageTitle(note);
            }
            
            // animationFrame(notesArray);
            // return;
        }

        // Handling for last note
        if (isLastNote) {
            const lastNoteVisible = isVisibleInViewport(note, 30) &&
                rect.right <= containerRect.right;
            
            if (lastNoteVisible) {
                hideObscuredShowPageTitle(note);
            } else {
                showObscuredHidePageTitle(note);
            }

            // animationFrame(notesArray);
            // return;
        }

        // Handling for notes in between
        const isVisible = isVisibleInViewport(note, 35);
        if (isVisible && rect.right <= containerRect.right && rect.left >= containerRect.left) {
            hideObscuredShowPageTitle(note);
        } else {
            showObscuredHidePageTitle(note);
        }

        animationFrame(notesArray);
        // return;
    });
}

function animationFrame(notesArray) {
    requestAnimationFrame(() => {
        notesArray.forEach(note => {
            const isVisible = isVisibleInViewport(note, 40);
            if (isVisible) {
                hideObscuredShowPageTitle(note);
            }
        });
    });
}