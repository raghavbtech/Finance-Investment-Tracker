// Sample data - this would normally be populated from your backend
document.addEventListener('DOMContentLoaded', function() {
    const ctx = document.getElementById('transactionChart').getContext('2d');
    
    // Create gradient for the line
    const gradient = ctx.createLinearGradient(0, 0, 0, 150);
    gradient.addColorStop(0, 'rgba(0, 247, 255, 0.5)');
    gradient.addColorStop(1, 'rgba(0, 247, 255, 0.1)');
    
    // Create gradient for the bar
    const barGradient = ctx.createLinearGradient(0, 0, 0, 150);
    barGradient.addColorStop(0, 'rgba(178, 75, 255, 0.7)');
    barGradient.addColorStop(1, 'rgba(178, 75, 255, 0.3)');

    // Sample data (would be populated from backend)
    const labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'];
    const expenseData = [500, 650, 420, 580, 490, 600];
    
    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    type: 'line',
                    label: 'Trend',
                    data: expenseData,
                    borderColor: '#00f7ff',
                    backgroundColor: gradient,
                    tension: 0.4,
                    borderWidth: 2,
                    pointBackgroundColor: '#00f7ff',
                    pointBorderColor: '#ffffff',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    fill: true
                },
                {
                    type: 'bar',
                    label: 'Amount',
                    data: expenseData,
                    backgroundColor: barGradient,
                    borderRadius: 6,
                    barPercentage: 0.5
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(26, 35, 50, 0.9)',
                    titleColor: '#00f7ff',
                    bodyColor: '#ffffff',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.7)',
                        callback: function(value) {
                            return '$' + value;
                        }
                    }
                }
            }
        }
    });
});