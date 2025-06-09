document.addEventListener('DOMContentLoaded', function () {
    const summaryRows = document.querySelectorAll('.expandable-summary-row');
    summaryRows.forEach(row => {
        const targetId = row.dataset.bsTarget;
        const detailsRow = document.querySelector(targetId);
        if (detailsRow) {
            detailsRow.addEventListener('show.bs.collapse', function () {
                const icon = row.querySelector('.toggle-icon');
                icon.innerHTML = '\u25BC'; // ▼
            });
            detailsRow.addEventListener('hide.bs.collapse', function () {
                const icon = row.querySelector('.toggle-icon');
                icon.innerHTML = '\u25B6'; // ►
            });
        }
    });
});
