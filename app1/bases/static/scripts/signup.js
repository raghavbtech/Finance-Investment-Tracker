document.addEventListener('DOMContentLoaded', () => {
    // Investment Growth Chart
    const investmentCtx = document.getElementById('investmentChart').getContext('2d');
    new Chart(investmentCtx, {
        type: 'line',
        data: {
            labels: ['2019', '2020', '2021', '2022', '2023'],
            datasets: [{
                label: 'Portfolio Growth',
                data: [10000, 15000, 25000, 40000, 65000],
                borderColor: '#00f7ff',
                backgroundColor: 'rgba(0, 247, 255, 0.1)',
                fill: true,
                tension: 0.4
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

    // Security Features Chart
    const securityCtx = document.getElementById('securityChart').getContext('2d');
    new Chart(securityCtx, {
        type: 'radar',
        data: {
            labels: ['Encryption', 'Authentication', 'Monitoring', 'Backup', 'Compliance'],
            datasets: [{
                label: 'Security Score',
                data: [95, 98, 92, 96, 94],
                backgroundColor: 'rgba(178, 75, 255, 0.2)',
                borderColor: '#b24bff',
                pointBackgroundColor: '#00f7ff',
                pointBorderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    pointLabels: { color: 'rgba(255, 255, 255, 0.7)' },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.7)',
                        backdropColor: 'transparent'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: { color: 'rgba(255, 255, 255, 0.7)' }
                }
            }
        }
    });

    // Add animation to benefit items
    document.querySelectorAll('.benefit-item').forEach((item, index) => {
        item.style.animation = `slideIn 0.5s ease forwards ${index * 0.1}s`;
    });
});