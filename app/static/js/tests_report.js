/**
 * Test Report Table — sorting + filtering
 *
 * All rows are server-rendered once. The JS reads the same normalized data via
 * /data, caches the original row pairs (summary + collapsible detail) by id,
 * and re-renders tbody in place whenever filters or sort change.
 */

const FILTER_CONFIG = [
    { id: 'filter-folder',      field: 'folder',      labelAll: 'All folders' },
    { id: 'filter-realm-type',  field: 'realm_type',  labelAll: 'All realm types' },
    { id: 'filter-realm',       field: 'realm',       labelAll: 'All realms' },
    { id: 'filter-class-name',  field: 'class_name',  labelAll: 'All classes' },
    { id: 'filter-outcome',     field: 'outcome',     labelAll: 'All outcomes', format: v => v.charAt(0).toUpperCase() + v.slice(1) },
];

const SEARCH_FIELDS = ['name', 'class_name', 'function_name', 'display_name', 'description'];

class TestReportTable {
    constructor(environment, timestamp) {
        this.environment = environment;
        this.timestamp = timestamp;
        this.tests = [];
        this.rowsById = {};
        this.filters = {};
        this.search = '';
        this.sort = { column: null, direction: 'asc' };

        this.table = document.getElementById('test-results-table');
        this.tbody = this.table ? this.table.querySelector('tbody') : null;
        this.countEl = document.getElementById('visible-count');
        this.noResultsEl = document.getElementById('no-results');
    }

    init() {
        if (!this.table || !this.tbody) return;
        this.cacheOriginalRows();
        this.attachSortListeners();
        this.loadData();
    }

    cacheOriginalRows() {
        Array.from(this.tbody.children).forEach(row => {
            if (row.tagName !== 'TR') return;
            const testId = row.getAttribute('data-test-id')
                || (row.id && row.id.startsWith('test-detail-') ? row.id.replace('test-detail-', '') : null);
            if (!testId) return;
            if (!this.rowsById[testId]) this.rowsById[testId] = [];
            this.rowsById[testId].push(row);
        });
    }

    loadData() {
        fetch(`/tests/${this.environment}/report/${this.timestamp}/data`)
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    console.error('Failed to load test data:', data.error);
                    return;
                }
                this.tests = data.tests || [];
                this.populateFilters();
                this.attachFilterListeners();
                this.render();
            })
            .catch(err => console.error('Error loading test data:', err));
    }

    populateFilters() {
        FILTER_CONFIG.forEach(cfg => {
            const el = document.getElementById(cfg.id);
            if (!el) return;
            const values = [...new Set(this.tests.map(t => t[cfg.field]).filter(Boolean))].sort();
            const current = el.value;
            el.innerHTML = `<option value="">${cfg.labelAll}</option>`;
            values.forEach(v => {
                const opt = document.createElement('option');
                opt.value = v;
                opt.textContent = cfg.format ? cfg.format(v) : v;
                el.appendChild(opt);
            });
            if (current) el.value = current;
        });
    }

    attachFilterListeners() {
        FILTER_CONFIG.forEach(cfg => {
            const el = document.getElementById(cfg.id);
            if (!el) return;
            el.addEventListener('change', e => {
                this.filters[cfg.field] = e.target.value;
                this.render();
            });
        });
        const searchEl = document.getElementById('filter-search');
        if (searchEl) {
            searchEl.addEventListener('input', e => {
                this.search = e.target.value.trim().toLowerCase();
                this.render();
            });
        }
    }

    attachSortListeners() {
        this.table.querySelectorAll('th[data-sort-column]').forEach(th => {
            th.addEventListener('click', e => {
                if (e.target.closest('select, input')) return;
                const column = th.getAttribute('data-sort-column');
                if (this.sort.column === column) {
                    this.sort.direction = this.sort.direction === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sort.column = column;
                    this.sort.direction = 'asc';
                }
                this.render();
            });
        });
    }

    updateSortIndicators() {
        this.table.querySelectorAll('th[data-sort-column]').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
            if (th.getAttribute('data-sort-column') === this.sort.column) {
                th.classList.add(`sort-${this.sort.direction}`);
            }
        });
    }

    matchesFilters(test) {
        for (const cfg of FILTER_CONFIG) {
            const expected = this.filters[cfg.field];
            if (expected && test[cfg.field] !== expected) return false;
        }
        if (this.search) {
            const haystack = SEARCH_FIELDS.map(f => (test[f] || '').toString().toLowerCase()).join(' ');
            if (!haystack.includes(this.search)) return false;
        }
        return true;
    }

    compare(a, b) {
        const col = this.sort.column;
        if (!col) return 0;
        let av = a[col], bv = b[col];
        if (av == null) av = '';
        if (bv == null) bv = '';
        if (typeof av === 'number' && typeof bv === 'number') {
            return this.sort.direction === 'asc' ? av - bv : bv - av;
        }
        av = String(av).toLowerCase();
        bv = String(bv).toLowerCase();
        return this.sort.direction === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
    }

    render() {
        this.updateSortIndicators();
        const visible = this.tests.filter(t => this.matchesFilters(t));
        if (this.sort.column) visible.sort((a, b) => this.compare(a, b));

        const fragment = document.createDocumentFragment();
        visible.forEach(t => {
            const rows = this.rowsById[String(t.id)];
            if (!rows) return;
            rows.forEach(r => fragment.appendChild(r.cloneNode(true)));
        });
        this.tbody.innerHTML = '';
        this.tbody.appendChild(fragment);

        if (this.countEl) this.countEl.textContent = visible.length;
        if (this.noResultsEl) this.noResultsEl.classList.toggle('d-none', visible.length > 0);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const ctx = document.querySelector('[data-environment][data-timestamp]');
    const environment = ctx?.getAttribute('data-environment');
    const timestamp = ctx?.getAttribute('data-timestamp');
    if (!environment || !timestamp) return;
    window.testReportTable = new TestReportTable(environment, timestamp);
    window.testReportTable.init();
});
