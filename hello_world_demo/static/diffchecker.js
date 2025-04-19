const diffButton = document.getElementById('diffButton');
const text1Input = document.getElementById('text1');
const text2Input = document.getElementById('text2');
const outputLeft = document.getElementById('output-left');
const outputRight = document.getElementById('output-right');
const lineNumbersLeft = document.getElementById('linenumbers-left');
const lineNumbersRight = document.getElementById('linenumbers-right');
const ignoreWhitespaceCheckbox = document.getElementById('ignoreWhitespaceCheckbox');

diffButton.addEventListener('click', () => {
    let text1 = text1Input.value;
    let text2 = text2Input.value;
    const ignoreWhitespace = ignoreWhitespaceCheckbox.checked;

    // Preprocess text if ignore whitespace is checked
    if (ignoreWhitespace) {
        // Simple approach: trim lines and normalize internal whitespace to single spaces
        const process = (text) => text.split('\n')
                                      .map(line => line.trim().replace(/\s+/g, ' '))
                                      .join('\n');
        text1 = process(text1);
        text2 = process(text2);
    }

    const dmp = new diff_match_patch();

    // Don't use linesToChars for this specific case, use direct diffing
    // This provides better control over newline handling
    const diffs = dmp.diff_main(text1, text2);
    dmp.diff_cleanupSemantic(diffs);

    // Process the diffs into lines
    const { htmlLeft, htmlRight, lineNumsLeft, lineNumsRight } = generateSideBySideHtml(diffs);

    outputLeft.innerHTML = htmlLeft;
    outputRight.innerHTML = htmlRight;
    lineNumbersLeft.innerHTML = lineNumsLeft;
    lineNumbersRight.innerHTML = lineNumsRight;
});

function generateSideBySideHtml(diffs) {
    let htmlLeft = '';
    let htmlRight = '';
    let lineNumsLeft = '';
    let lineNumsRight = '';
    let lineNumLeft = 1;
    let lineNumRight = 1;

    // Helper to escape HTML characters
    const escapeHtml = (unsafe) => {
        if (!unsafe) return '';
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    };

    // Process the diffs into lines for display
    let leftLines = [];
    let rightLines = [];
    
    // First pass: process the diffs into lines
    let currentLeft = '';
    let currentRight = '';
    
    for (let i = 0; i < diffs.length; i++) {
        const [op, text] = diffs[i];
        
        if (op === 0) { // EQUAL
            // For EQUAL chunks, add to both sides
            const lines = text.split('\n');
            
            for (let j = 0; j < lines.length; j++) {
                if (j > 0) {
                    // We hit a newline, push current buffers to arrays
                    leftLines.push(currentLeft);
                    rightLines.push(currentRight);
                    currentLeft = '';
                    currentRight = '';
                }
                
                // Add current line to both buffers
                currentLeft += lines[j];
                currentRight += lines[j];
            }
            
            // If text ends with newline, push current buffers
            if (text.endsWith('\n')) {
                leftLines.push(currentLeft);
                rightLines.push(currentRight);
                currentLeft = '';
                currentRight = '';
            }
        } else if (op === -1) { // DELETE
            // For DELETE chunks, add to left side only
            const lines = text.split('\n');
            
            for (let j = 0; j < lines.length; j++) {
                if (j > 0) {
                    // We hit a newline, push current buffers
                    leftLines.push(currentLeft);
                    if (currentRight !== '') {
                        rightLines.push(currentRight);
                        currentRight = '';
                    } else {
                        rightLines.push(null); // Placeholder
                    }
                    currentLeft = '';
                }
                
                // Add current line to left buffer only
                currentLeft += lines[j];
            }
            
            // If text ends with newline, push current buffers
            if (text.endsWith('\n')) {
                leftLines.push(currentLeft);
                if (currentRight !== '') {
                    rightLines.push(currentRight);
                    currentRight = '';
                } else {
                    rightLines.push(null); // Placeholder
                }
                currentLeft = '';
            }
        } else if (op === 1) { // INSERT
            // For INSERT chunks, add to right side only
            const lines = text.split('\n');
            
            for (let j = 0; j < lines.length; j++) {
                if (j > 0) {
                    // We hit a newline, push current buffers
                    if (currentLeft !== '') {
                        leftLines.push(currentLeft);
                        currentLeft = '';
                    } else {
                        leftLines.push(null); // Placeholder
                    }
                    rightLines.push(currentRight);
                    currentRight = '';
                }
                
                // Add current line to right buffer only
                currentRight += lines[j];
            }
            
            // If text ends with newline, push current buffers
            if (text.endsWith('\n')) {
                if (currentLeft !== '') {
                    leftLines.push(currentLeft);
                    currentLeft = '';
                } else {
                    leftLines.push(null); // Placeholder
                }
                rightLines.push(currentRight);
                currentRight = '';
            }
        }
    }
    
    // Push any remaining content
    if (currentLeft !== '' || currentRight !== '') {
        leftLines.push(currentLeft);
        rightLines.push(currentRight);
    }
    
    // Ensure arrays are the same length by padding with nulls
    while (leftLines.length < rightLines.length) {
        leftLines.push(null);
    }
    while (rightLines.length < leftLines.length) {
        rightLines.push(null);
    }
    
    // Second pass: generate HTML
    for (let i = 0; i < leftLines.length; i++) {
        const leftLine = leftLines[i];
        const rightLine = rightLines[i];
        
        if (leftLine !== null && rightLine !== null && leftLine === rightLine) {
            // Equal lines
            const cleanLine = escapeHtml(leftLine) || '&nbsp;';
            htmlLeft += `<div>${cleanLine}</div>`;
            htmlRight += `<div>${cleanLine}</div>`;
            lineNumsLeft += `<div>${lineNumLeft++}</div>`;
            lineNumsRight += `<div>${lineNumRight++}</div>`;
        } else {
            // Different or null lines
            if (leftLine !== null) {
                htmlLeft += `<div class="diff-deleted">${escapeHtml(leftLine) || '&nbsp;'}</div>`;
                lineNumsLeft += `<div class="diff-deleted">${lineNumLeft++}</div>`;
            } else {
                htmlLeft += `<div class="diff-placeholder">&nbsp;</div>`;
                lineNumsLeft += `<div class="diff-placeholder"></div>`;
            }
            
            if (rightLine !== null) {
                htmlRight += `<div class="diff-inserted">${escapeHtml(rightLine) || '&nbsp;'}</div>`;
                lineNumsRight += `<div class="diff-inserted">${lineNumRight++}</div>`;
            } else {
                htmlRight += `<div class="diff-placeholder">&nbsp;</div>`;
                lineNumsRight += `<div class="diff-placeholder"></div>`;
            }
        }
    }

    return { htmlLeft, htmlRight, lineNumsLeft, lineNumsRight };
}

// Initial setup or clear function can be added if needed
// function clearOutputs() {
//     outputLeft.innerHTML = '';
//     outputRight.innerHTML = '';
//     lineNumbersLeft.innerHTML = '';
//     lineNumbersRight.innerHTML = '';
// } 