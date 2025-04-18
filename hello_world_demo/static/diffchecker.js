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
        // Note: This diffs the processed text. The display will still show original text,
        // but highlights are based on the processed comparison.
        // A more advanced version might map changes back to original positions.
    }

    const dmp = new diff_match_patch();
    // Use diff_linesToChars for better line-based alignment in side-by-side
    const a = dmp.diff_linesToChars_(text1, text2);
    const lineText1 = a.chars1;
    const lineText2 = a.chars2;
    const lineArray = a.lineArray;

    const diffs = dmp.diff_main(lineText1, lineText2, false);
    dmp.diff_charsToLines_(diffs, lineArray);
    dmp.diff_cleanupSemantic(diffs); // Optional cleanup

    const { htmlLeft, htmlRight, lineNumsLeft, lineNumsRight } = generateSideBySideHtml(diffs, ignoreWhitespace);

    outputLeft.innerHTML = htmlLeft;
    outputRight.innerHTML = htmlRight;
    lineNumbersLeft.innerHTML = lineNumsLeft;
    lineNumbersRight.innerHTML = lineNumsRight;

});

function generateSideBySideHtml(diffs, ignoreWhitespace) {
    let htmlLeft = '';
    let htmlRight = '';
    let lineNumsLeft = '';
    let lineNumsRight = '';
    let lineNumLeft = 1;
    let lineNumRight = 1;

    // Helper to escape HTML characters
    const escapeHtml = (unsafe) => {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    };

    // Helper to generate diff for a single line (character-level highlighting)
    const generateLineDiff = (text1, text2) => {
        const dmp = new diff_match_patch();
        let lineDiffs = dmp.diff_main(text1, text2);
        dmp.diff_cleanupSemanticLossless(lineDiffs); // Use lossless for char highlighting

        let lineHtml1 = '';
        let lineHtml2 = '';
        for (const [op, data] of lineDiffs) {
            const escapedData = escapeHtml(data);
            if (op === 0) { // EQUAL
                lineHtml1 += escapedData;
                lineHtml2 += escapedData;
            } else if (op === -1) { // DELETE
                lineHtml1 += `<del>${escapedData}</del>`;
            } else if (op === 1) { // INSERT
                lineHtml2 += `<ins>${escapedData}</ins>`;
            }
        }
        // Add non-breaking space if line is empty to maintain height
        return {
            left: lineHtml1 || '&nbsp;',
            right: lineHtml2 || '&nbsp;'
        };
    };

    for (let i = 0; i < diffs.length; i++) {
        const [op, data] = diffs[i];
        const lines = data.split('\n');
        // The last element is usually an empty string after the last \n, remove it
        if (lines[lines.length - 1] === '') {
            lines.pop();
        }

        for (let j = 0; j < lines.length; j++) {
            const line = lines[j];
             // If ignoring whitespace, we still show original line but highlight based on processed
             // For simplicity here, we apply diff highlighting based on line presence/absence
             // True character diff on original while ignoring whitespace requires complex mapping.
            const escapedLine = escapeHtml(line);

            if (op === 0) { // EQUAL
                // Perform char diff on equal lines for finer granularity
                const nextDiff = diffs[i+1];
                let lineDiff = { left: escapedLine || '&nbsp;', right: escapedLine || '&nbsp;' };
                // Heuristic: If the equal block is followed by an insert/delete block
                // affecting the *next* line, and we are on the last line of the current equal block,
                // perform char diff to highlight changes leading into the insert/delete.
                // This helps catch changes where a line is modified rather than fully replaced.
                // A more robust approach might compare original lines mapped back from chars.
                if (j === lines.length - 1 && nextDiff && nextDiff[0] !== 0) {
                    // Crude check: assume the next diff's data corresponds to the changed line.
                    // This won't be perfect for complex multi-line changes.
                    if (nextDiff[0] === -1) { // Deletion follows
                         lineDiff = generateLineDiff(line, ''); // Compare line against empty
                    } else if (nextDiff[0] === 1) { // Insertion follows
                         lineDiff = generateLineDiff('', line); // Compare empty against line (this is less useful)
                         // Let's try comparing with the first line of the insertion instead?
                         const nextLines = nextDiff[1].split('\n');
                         if (nextLines.length > 0) {
                            lineDiff = generateLineDiff(line, nextLines[0]);
                         }
                    }
                    // Experimental: Always run char diff on EQUAL lines if not ignoring whitespace?
                    // if (!ignoreWhitespace) {
                    //     lineDiff = generateLineDiff(line, line); // This seems wrong, need the peer line
                    // }
                } else if (!ignoreWhitespace && lines.length === 1) {
                    // If it's a single equal line block and not ignoring whitespace, maybe char diff?
                    // Still needs the peer line info, which diff_linesToChars doesn't easily provide here.
                    // Fallback to simple display for now.
                } else {
                     // Default: Just display the line as equal
                     lineDiff = { left: escapedLine || '&nbsp;', right: escapedLine || '&nbsp;' };
                }

                // More reliable approach: If not ignoring whitespace, always generate char diff for equal lines.
                // Requires mapping original lines correctly.
                if (!ignoreWhitespace) {
                     // Problem: We don't have the corresponding line from the *other* file easily here.
                     // The lineArray from diff_linesToChars_ only contains the unique lines.
                     // Reverting to simpler display for now.
                     lineDiff = generateLineDiff(line, line); // Compare line with itself (will show no diff)
                     htmlLeft += `<div>${lineDiff.left}</div>`;
                     htmlRight += `<div>${lineDiff.right}</div>`;
                } else {
                     // If ignoring whitespace, don't do char diff for EQUAL lines.
                    htmlLeft += `<div>${escapedLine || '&nbsp;'}</div>`;
                    htmlRight += `<div>${escapedLine || '&nbsp;'}</div>`;
                }

                lineNumsLeft += `<div>${lineNumLeft}</div>`;
                lineNumsRight += `<div>${lineNumRight}</div>`;
                lineNumLeft++;
                lineNumRight++;
            } else if (op === -1) { // DELETE
                 const lineDiff = generateLineDiff(line, ''); // Char diff against empty
                 htmlLeft += `<div class="diff-deleted">${lineDiff.left}</div>`;
                 htmlRight += `<div class="diff-placeholder">&nbsp;</div>`;
                 lineNumsLeft += `<div class="diff-deleted">${lineNumLeft}</div>`;
                 lineNumsRight += `<div class="diff-placeholder"></div>`; // Fixed: Empty div
                 lineNumLeft++;
            } else if (op === 1) { // INSERT
                const lineDiff = generateLineDiff('', line); // Char diff against empty
                htmlLeft += `<div class="diff-placeholder">&nbsp;</div>`;
                htmlRight += `<div class="diff-inserted">${lineDiff.right}</div>`;
                lineNumsLeft += `<div class="diff-placeholder"></div>`; // Fixed: Empty div
                lineNumsRight += `<div class="diff-inserted">${lineNumRight}</div>`;
                lineNumRight++;
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