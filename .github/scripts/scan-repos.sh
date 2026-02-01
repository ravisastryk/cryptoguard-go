#!/bin/bash
set -e

# CryptoGuard-Go Weekly Repository Scanner
# This script scans multiple Go repositories for cryptographic vulnerabilities

echo "CryptoGuard-Go Repository Scanner"
echo "===================================="
echo ""

# Create output directories
mkdir -p scan-results
mkdir -p reports

# Configuration
# Load settings from config file
CONFIG_FILE=".github/scan-config.yml"

if [ -f "$CONFIG_FILE" ]; then
    echo "[INFO] Loading configuration from $CONFIG_FILE"
    # Extract excluded repos (simple grep/sed parsing)
    EXCLUDED_REPOS=($(grep -A100 "excluded_repos:" "$CONFIG_FILE" | grep "  - " | sed 's/.*- //' | grep -v "^#"))

    # Load scan settings
    MAX_REPOS=$(grep "max_repos:" "$CONFIG_FILE" | sed 's/.*max_repos: //' || echo "10")
    MIN_STARS=$(grep "min_stars:" "$CONFIG_FILE" | sed 's/.*min_stars: //' || echo "100")
    MIN_FORKS=$(grep "min_forks:" "$CONFIG_FILE" | sed 's/.*min_forks: //' || echo "50")
else
    # Fallback to defaults if config not found
    MAX_REPOS=10
    MIN_STARS=100
    MIN_FORKS=50
    EXCLUDED_REPOS=()
fi

# Display exclusion list
if [ ${#EXCLUDED_REPOS[@]} -gt 0 ]; then
    echo "[INFO] Excluded repositories: ${EXCLUDED_REPOS[*]}"
    echo ""
fi

echo "Fetching top Go repositories from GitHub..."
echo "Criteria: stars >= $MIN_STARS, forks >= $MIN_FORKS"
echo ""

# Setup GitHub API authentication if token is available
CURL_HEADERS=""
if [ -n "$GITHUB_TOKEN" ]; then
    CURL_HEADERS="-H \"Authorization: token $GITHUB_TOKEN\""
    echo "[INFO] Using authenticated GitHub API (higher rate limits)"
else
    echo "[INFO] Using unauthenticated GitHub API (60 requests/hour limit)"
fi
echo ""

# Extract repository full names (owner/repo)
REPOS=()
for page in {1..10}; do
    echo "Fetching page $page of top repositories..."

    # Build curl command with optional authentication
    if [ -n "$GITHUB_TOKEN" ]; then
        PAGE_DATA=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
            "https://api.github.com/search/repositories?q=language:Go+stars:>=$MIN_STARS+forks:>=$MIN_FORKS&sort=stars&order=desc&per_page=100&page=$page")
    else
        PAGE_DATA=$(curl -s \
            "https://api.github.com/search/repositories?q=language:Go+stars:>=$MIN_STARS+forks:>=$MIN_FORKS&sort=stars&order=desc&per_page=100&page=$page")
    fi

    # Check for API rate limit
    if echo "$PAGE_DATA" | grep -q "API rate limit exceeded"; then
        echo "[ERROR] GitHub API rate limit exceeded. Set GITHUB_TOKEN environment variable for higher limits."
        break
    fi

    # Extract repo names using grep and sed (works without jq)
    PAGE_REPOS=$(echo "$PAGE_DATA" | grep '"full_name":' | sed 's/.*"full_name": "\([^"]*\)".*/\1/')

    # Add to array
    while IFS= read -r repo; do
        if [ -n "$repo" ]; then
            REPOS+=("$repo")
        fi
    done <<< "$PAGE_REPOS"

    # Stop if we have enough repos or if page is empty
    if [ ${#REPOS[@]} -ge $MAX_REPOS ] || [ -z "$PAGE_REPOS" ]; then
        break
    fi

    # Rate limit protection
    sleep 1
done

# Limit to MAX_REPOS
if [ ${#REPOS[@]} -gt $MAX_REPOS ]; then
    REPOS=("${REPOS[@]:0:$MAX_REPOS}")
fi

# Filter out excluded repositories
if [ ${#EXCLUDED_REPOS[@]} -gt 0 ]; then
    FILTERED_REPOS=()
    for repo in "${REPOS[@]}"; do
        excluded=false
        for excluded_repo in "${EXCLUDED_REPOS[@]}"; do
            if [ "$repo" = "$excluded_repo" ]; then
                echo "[SKIP] Excluding $repo (in exclusion list)"
                excluded=true
                break
            fi
        done
        if [ "$excluded" = false ]; then
            FILTERED_REPOS+=("$repo")
        fi
    done
    REPOS=("${FILTERED_REPOS[@]}")
fi

# Counters
TOTAL_REPOS=0
REPOS_WITH_ISSUES=0
TOTAL_ISSUES=0

echo ""
echo "Total repositories to scan: ${#REPOS[@]}"
echo ""

# Scan each repository
for repo in "${REPOS[@]}"; do
    TOTAL_REPOS=$((TOTAL_REPOS + 1))

    echo "-------------------------------------------"
    echo "[$TOTAL_REPOS/${#REPOS[@]}] Scanning: $repo"
    echo "-------------------------------------------"

    # Extract owner and repo name
    OWNER=$(echo "$repo" | cut -d'/' -f1)
    REPO_NAME=$(echo "$repo" | cut -d'/' -f2)

    # Create temp directory
    TEMP_DIR="temp-scan-$REPO_NAME"

    # Clone repository (shallow clone for speed)
    echo "Cloning repository..."
    if git clone --depth 1 "https://github.com/$repo.git" "$TEMP_DIR" 2>/dev/null; then
        echo "[OK] Repository cloned successfully"

        cd "$TEMP_DIR"

        # Check if it's a Go project
        if [ -f "go.mod" ]; then
            echo "[OK] Go project detected"

            # Run CryptoGuard-Go
            echo "Running CryptoGuard-Go analysis..."

            # Scan and save results
            RESULT_FILE="../scan-results/${OWNER}-${REPO_NAME}.txt"
            JSON_FILE="../scan-results/${OWNER}-${REPO_NAME}.json"

            # Run scan (capture exit code)
            set +e
            ../cryptoguard -format text ./... > "$RESULT_FILE" 2>&1
            SCAN_EXIT_CODE=$?

            ../cryptoguard -format json ./... > "$JSON_FILE" 2>&1
            set -e

            # Count issues
            ISSUE_COUNT=$(grep -c "issue(s) found" "$RESULT_FILE" | grep -oE '[0-9]+' || echo "0")

            if [ "$SCAN_EXIT_CODE" -eq 1 ] || grep -q "issue(s) found" "$RESULT_FILE"; then
                echo "[WARNING] Found cryptographic issues"
                REPOS_WITH_ISSUES=$((REPOS_WITH_ISSUES + 1))

                # Extract issue count from the last line
                ISSUES=$(tail -1 "$RESULT_FILE" | grep -oE '[0-9]+' || echo "0")
                TOTAL_ISSUES=$((TOTAL_ISSUES + ISSUES))

                echo "         Issues found: $ISSUES"
            else
                echo "[OK] No cryptographic issues found"
            fi
        else
            echo "[INFO] Not a Go project (no go.mod found)"
        fi

        cd ..

        # Cleanup
        rm -rf "$TEMP_DIR"

    else
        echo "[ERROR] Failed to clone repository"
    fi

    echo ""
done

echo "=========================================="
echo "Scan Summary"
echo "=========================================="
echo "Total repositories scanned: $TOTAL_REPOS"
echo "Repositories with issues: $REPOS_WITH_ISSUES"
echo "Total issues found: $TOTAL_ISSUES"
echo ""

# Save summary
cat > scan-results/summary.txt <<EOF
CryptoGuard-Go Scan Summary
===========================
Date: $(date)
Total repositories scanned: $TOTAL_REPOS
Repositories with issues: $REPOS_WITH_ISSUES
Total issues found: $TOTAL_ISSUES
EOF

echo "[COMPLETE] Scan complete. Results saved to scan-results/"
