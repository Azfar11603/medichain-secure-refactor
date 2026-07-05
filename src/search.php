<?php
/**
 * search.php — REFACTORED (secure)
 *
 * Fixes two vulnerabilities found in the legacy version:
 *   1. SQL Injection  — legacy code concatenated $_GET['keyword'] directly
 *      into the SQL string, so the DB engine parsed attacker input as
 *      part of the command itself.
 *   2. Reflected XSS  — legacy code echoed $_GET['keyword'] straight into
 *      the HTML response with no encoding, so a <script> payload was
 *      parsed and executed by the browser.
 *
 * Fix strategy:
 *   - Use a parameterized (prepared) statement so the query template is
 *     compiled BEFORE user input exists in the pipeline. The bound value
 *     travels to the DB driver as a literal on a separate channel and can
 *     never be re-parsed as SQL syntax, regardless of its content.
 *   - Use htmlspecialchars() at the exact point data enters the HTML
 *     output stream (the "sink"), so <, >, ", ', & are converted to
 *     harmless entities and the browser's parser never sees tag syntax.
 */

declare(strict_types=1);

// --- Input ---------------------------------------------------------------
$keyword = $_GET['keyword'] ?? '';

// --- Data-access plane: parameterized query (fixes SQL Injection) --------
// The query text ("SELECT ... WHERE name LIKE ?") is compiled by the DB
// engine into an execution plan first. Only after that plan exists does
// bind_param() attach the actual value. The value is never spliced into
// the SQL string, so it cannot alter the query's structure.
$sql = "SELECT id, name, illness_history FROM patient_records WHERE name LIKE ?";
$stmt = $conn->prepare($sql);

if ($stmt === false) {
    http_response_code(500);
    exit('Unable to process search request.');
}

// Wildcards are appended to the search term BEFORE binding, not by
// concatenating the raw value into the query text.
$searchTerm = '%' . $keyword . '%';
$stmt->bind_param('s', $searchTerm);
$stmt->execute();

$result = $stmt->get_result();

// --- Output plane: context-aware encoding (fixes Reflected XSS) ---------
// Encoding happens at the sink — the exact point data is written into the
// HTML response — not upstream via a generic filter/blocklist. This
// neutralises the characters the HTML parser needs to exit text mode,
// regardless of what the payload contains.
$safeKeyword = htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8');
echo '<div class="search-summary">Results for: ' . $safeKeyword . '</div>';

echo '<ul class="patient-results">';
while ($row = $result->fetch_assoc()) {
    $safeName = htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8');
    $safeHistory = htmlspecialchars($row['illness_history'], ENT_QUOTES, 'UTF-8');
    echo '<li><strong>' . $safeName . '</strong>: ' . $safeHistory . '</li>';
}
echo '</ul>';

$stmt->close();
