
// Charts initialization
document.addEventListener('DOMContentLoaded', function() {
    // Monthly Expense Chart
    const expenseCtx = document.getElementById('expenseChart').getContext('2d');
    const expenseChart = new Chart(expenseCtx, {
        type: 'line',
        data: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            datasets: [{
                label: 'Income',
                data: [6500, 7200, 8100, 8940, 0, 0],
                borderColor: '#4ecca3',
                backgroundColor: 'rgba(78, 204, 163, 0.1)',
                tension: 0.4,
                fill: true,
                borderWidth: 3
            }, {
                label: 'Expenses',
                data: [4200, 4800, 5100, 5320, 0, 0],
                borderColor: '#ff2e88',
                backgroundColor: 'rgba(255, 46, 136, 0.1)',
                tension: 0.4,
                fill: true,
                borderWidth: 3
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: 'rgba(255, 255, 255, 0.7)',
                        font: {
                            family: "'Lexend', sans-serif",
                            size: 12
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.7)',
                        callback: function(value) {
                            return '$' + value;
                        }
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            }
        }
    });

    // Category Chart
    const categoryCtx = document.getElementById('categoryChart').getContext('2d');
    const categoryChart = new Chart(categoryCtx, {
        type: 'doughnut',
        data: {
            labels: ['Housing', 'Food', 'Transportation', 'Entertainment', 'Utilities', 'Others'],
            datasets: [{
                data: [42, 18, 12, 9, 15, 4],
                backgroundColor: [
                    '#00f7ff',
                    '#b24bff',
                    '#ff2e88',
                    '#4ecca3',
                    '#f7d038',
                    '#5356FF'
                ],
                borderWidth: 2,
                borderColor: 'rgba(26, 35, 50, 0.8)'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: 'rgba(255, 255, 255, 0.7)',
                        font: {
                            family: "'Lexend', sans-serif",
                            size: 12
                        },
                        padding: 15
                    }
                }
            },
            cutout: '65%'
        }
    });
});