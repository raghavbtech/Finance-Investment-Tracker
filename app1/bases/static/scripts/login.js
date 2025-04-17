document.addEventListener('DOMContentLoaded', () => {
    new Chart(document.getElementById('marketChart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Stocks', 'Crypto', 'Forex', 'Commodities'],
            datasets: [{
                data: [40, 25, 20, 15],
                backgroundColor: ['#ff2e88', '#00f7ff', '#4ecca3', '#b24bff']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: 'rgba(255, 255, 255, 0.7)' }
                }
            }
        }
    });

    new Chart(document.getElementById('activityChart').getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
            datasets: [{
                label: 'Trading Volume',
                data: [1200, 1900, 1500, 2100, 1800],
                backgroundColor: '#ff2e88',
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: 'rgba(255, 255, 255, 0.7)' }
                }
            },
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: 'rgba(255, 255, 255, 0.7)' }
                },
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: 'rgba(255, 255, 255, 0.7)' }
                }
            }
        }
    });
});