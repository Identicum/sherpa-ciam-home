document.addEventListener('DOMContentLoaded', function () {
    const summaryRows = document.querySelectorAll('.expandable-summary-row');
    summaryRows.forEach(row => {
        row.addEventListener('click', function () {
            const targetId = this.dataset.targetId;
            const detailsRow = document.getElementById(targetId);
            const icon = this.querySelector('.toggle-icon');
            if (detailsRow) {
                if (detailsRow.style.display === 'none' || detailsRow.style.display === '') {
                    detailsRow.style.display = 'table-row';
                    icon.innerHTML = '\u25BC'; // ▼
                } else {
                    detailsRow.style.display = 'none';
                    icon.innerHTML = '\u25B6'; // ►
                }
            }
        });
    });
});
