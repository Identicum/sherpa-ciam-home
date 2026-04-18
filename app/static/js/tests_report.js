/**
 * Test Report Table Sorting and Filtering
 * Handles interactive sorting and filtering of the test report table
 */

class TestReportTable {
    constructor(environment, timestamp) {
        this.environment = environment;
        this.timestamp = timestamp;
        this.originalTests = [];
        this.filteredTests = [];
        this.currentSort = { column: null, direction: 'asc' };
        this.filters = {};
        this.originalRowsMap = {}; // Store original rows once
        this.init();
    }

    init() {
        this.attachColumnHeaderListeners();
        this.loadTestData();
    }

    /**
     * Load test data from the API endpoint
     */
    loadTestData() {
        const dataUrl = `/tests/${this.environment}/report/${this.timestamp}/data`;
        // console.log('Loading test data from:', dataUrl);
        fetch(dataUrl)
            .then(response => response.json())
            .then(data => {
                // console.log('Received test data:', data);
                if (data.success) {
                    this.originalTests = data.tests;
                    this.filteredTests = [...this.originalTests];
                    // console.log('Loaded tests:', this.originalTests.length, 'tests');
                    // Delay caching to ensure all DOM elements are fully rendered
                    setTimeout(() => {
                        this.cacheOriginalRows();
                        this.updateFilterOptions();
                        this.attachFilterListeners();
                    }, 100);
                } else {
                    console.error('Failed to load test data:', data.error);
                }
            })
            .catch(error => console.error('Error loading test data:', error));
    }

    /**
     * Cache original rows from the HTML table before any modifications
     */
    cacheOriginalRows() {
        // Find the test results table by its ID
        const mainTable = document.getElementById('test-results-table');
        const tbody = mainTable ? mainTable.querySelector('tbody') : null;
        // console.log('cacheOriginalRows - tbody found:', !!tbody);
        if (!tbody) {
            console.warn('No tbody found for caching rows');
            return;
        }

        // Only get direct children <tr> elements (not nested ones from detail tables)
        const allRows = Array.from(tbody.children).filter(el => el.tagName === 'TR');
        // console.log('cacheOriginalRows - total rows found:', allRows.length);
        allRows.forEach((row, index) => {
            const testId = row.getAttribute('data-test-id');
            // console.log(`Row ${index} - data-test-id: ${testId}, id: ${row.id}, classes: ${row.className}`);
            if (testId) {
                if (!this.originalRowsMap[testId]) {
                    this.originalRowsMap[testId] = [];
                }
                this.originalRowsMap[testId].push(row);
                // console.log(`  -> Cached as summary row for test ID: ${testId}`);
            } else if (row.id && row.id.startsWith('test-detail-')) {
                // This is a detail row (has id like test-detail-X)
                const testId = row.id.replace('test-detail-', '');
                if (!this.originalRowsMap[testId]) {
                    this.originalRowsMap[testId] = [];
                }
                this.originalRowsMap[testId].push(row);
                // console.log(`  -> Cached as detail row for test ID: ${testId}`);
            }
        });
        // console.log('Final cached original rows for test IDs:', Object.keys(this.originalRowsMap));
    }

    /**
     * Attach click listeners to column headers for sorting
     */
    attachColumnHeaderListeners() {
        const mainTable = document.getElementById('test-results-table');
        if (!mainTable) return;
        const headers = mainTable.querySelectorAll('th[data-sort-column]');
        headers.forEach(header => {
            header.style.cursor = 'pointer';
            header.addEventListener('click', (e) => {
                // Don't sort if clicking on the filter dropdown
                if (e.target.id === 'filter-outcome' || e.target.closest('select')) {
                    return;
                }
                const column = header.getAttribute('data-sort-column');
                this.handleSort(column);
            });
        });
    }

    /**
     * Handle column header click for sorting
     */
    handleSort(column) {
        // Toggle direction if clicking the same column
        if (this.currentSort.column === column) {
            this.currentSort.direction = this.currentSort.direction === 'asc' ? 'desc' : 'asc';
        } else {
            this.currentSort.column = column;
            this.currentSort.direction = 'asc';
        }
        
        this.updateSortIndicators();
        this.applyFiltersAndSort();
    }

    /**
     * Update visual indicators for sort direction
     */
    updateSortIndicators() {
        const mainTable = document.getElementById('test-results-table');
        if (!mainTable) return;
        const headers = mainTable.querySelectorAll('th[data-sort-column]');
        headers.forEach(header => {
            header.classList.remove('sort-asc', 'sort-desc');
            const column = header.getAttribute('data-sort-column');
            if (column === this.currentSort.column) {
                header.classList.add(`sort-${this.currentSort.direction}`);
            }
        });
    }

    /**
     * Get available filter values for a column
     */
    getFilterValues(column) {
        const values = new Set();
        this.originalTests.forEach(test => {
            const value = test[column];
            if (value) {
                values.add(value);
            }
        });
        const result = Array.from(values).sort();
        // console.log(`getFilterValues('${column}'):`, result);
        return result;
    }

    /**
     * Update filter UI with available options
     */
    updateFilterOptions() {
        const outcomeFilter = document.getElementById('filter-outcome');
        // console.log('updateFilterOptions - Filter element found:', !!outcomeFilter);
        if (outcomeFilter) {
            const values = this.getFilterValues('outcome');
            // console.log('Outcome filter values:', values);
            const currentValue = outcomeFilter.value;
            // Preserve current selection
            outcomeFilter.innerHTML = '<option value="">All</option>';
            values.forEach(value => {
                const option = document.createElement('option');
                option.value = value;
                option.textContent = value.charAt(0).toUpperCase() + value.slice(1);
                outcomeFilter.appendChild(option);
            });
            if (currentValue) {
                outcomeFilter.value = currentValue;
            }
            // console.log('Filter options updated with', values.length, 'unique values');
        } else {
            console.warn('Filter element #filter-outcome not found');
        }
    }

    /**
     * Attach listeners to filter controls
     */
    attachFilterListeners() {
        // Find filter within the test results table
        const mainTable = document.getElementById('test-results-table');
        if (!mainTable) return;
        const outcomeFilter = mainTable.querySelector('#filter-outcome');
        if (outcomeFilter) {
            outcomeFilter.addEventListener('change', (e) => {
                this.filters.outcome = e.target.value;
                this.applyFiltersAndSort();
            });
        }
    }

    /**
     * Apply filters and sort to test data
     */
    applyFiltersAndSort() {
        // Apply filters
        this.filteredTests = this.originalTests.filter(test => {
            if (this.filters.outcome && test.outcome !== this.filters.outcome) {
                return false;
            }
            return true;
        });
        // Apply sort
        if (this.currentSort.column) {
            this.filteredTests.sort((a, b) => {
                let aVal = a[this.currentSort.column];
                let bVal = b[this.currentSort.column];
                // Handle numeric values
                if (typeof aVal === 'number' && typeof bVal === 'number') {
                    return this.currentSort.direction === 'asc' ? aVal - bVal : bVal - aVal;
                }
                // Handle string values
                aVal = String(aVal).toLowerCase();
                bVal = String(bVal).toLowerCase();
                if (this.currentSort.direction === 'asc') {
                    return aVal.localeCompare(bVal);
                } else {
                    return bVal.localeCompare(aVal);
                }
            });
        }
        // console.log('Filtered tests:', this.filteredTests.length, 'Sort column:', this.currentSort.column, 'Direction:', this.currentSort.direction);
        // Update table display
        this.updateTableDisplay();
    }

    /**
     * Update table display with filtered/sorted data
     */
    updateTableDisplay() {
        const mainTable = document.getElementById('test-results-table');
        if (!mainTable) return;
        const tbody = mainTable.querySelector('tbody');
        // console.log('Updating table display with', this.filteredTests.length, 'visible tests');
        // Create a fragment to hold reordered rows
        const fragment = document.createDocumentFragment();
        // Add filtered/sorted rows to fragment in correct order
        this.filteredTests.forEach((test) => {
            const testId = test.id.toString();
            const rowsToAdd = this.originalRowsMap[testId];
            if (rowsToAdd) {
                rowsToAdd.forEach(row => {
                    fragment.appendChild(row.cloneNode(true));
                });
            }
        });
        // Clear tbody and add reordered rows
        tbody.innerHTML = '';
        tbody.appendChild(fragment);
        // console.log('Table display updated');
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Get environment and timestamp from page context
    const containerElement = document.querySelector('[data-environment][data-timestamp]');
    const environment = containerElement?.getAttribute('data-environment');
    const timestamp = containerElement?.getAttribute('data-timestamp');
    // console.log('Initializing TestReportTable - Environment:', environment, 'Timestamp:', timestamp);
    if (environment && timestamp) {
        window.testReportTable = new TestReportTable(environment, timestamp);
    } else {
        console.error('Could not find environment or timestamp in page attributes');
    }
});
