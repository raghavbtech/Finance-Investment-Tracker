// Add loading state to form submission
document.querySelector('.profile-form').addEventListener('submit', function(e) {
    const saveBtn = document.querySelector('.btn-save');
    const saveText = document.querySelector('.save-text');
    
    saveBtn.style.pointerEvents = 'none';
    saveBtn.style.opacity = '0.8';
    
    // Create loading spinner
    const loader = document.createElement('span');
    loader.className = 'loading';
    saveBtn.prepend(loader);
    
    // Optional: Update progress bar
    document.querySelector('.progress-bar').style.width = '100%';
});

// Add animation to form fields when they come into focus
const formGroups = document.querySelectorAll('.form-group');
formGroups.forEach(group => {
    const input = group.querySelector('input, textarea, select');
    if (input) {
        input.addEventListener('focus', () => {
            group.classList.add('focused');
        });
        
        input.addEventListener('blur', () => {
            if (!input.value) {
                group.classList.remove('focused');
            }
        });
        
        // Check if input already has value
        if (input.value) {
            group.classList.add('focused');
        }
    }
});

// Chart.js initialization
// Activity Chart
const activityCtx = document.getElementById('activityChart').getContext('2d');
const activityChart = new Chart(activityCtx, {
    type: 'line',
    data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [{
            label: 'Activity Level',
            data: [12, 19, 15, 28, 22, 30],
            backgroundColor: 'rgba(0, 247, 255, 0.2)',
            borderColor: '#00f7ff',
            borderWidth: 2,
            tension: 0.4,
            fill: true,
            pointBackgroundColor: '#00f7ff',
            pointBorderColor: '#1a2332',
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 6
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)'
                },
                ticks: {
                    color: 'rgba(255, 255, 255, 0.7)'
                }
            },
            x: {
                grid: {
                    display: false
                },
                ticks: {
                    color: 'rgba(255, 255, 255, 0.7)'
                }
            }
        },
        plugins: {
            legend: {
                display: false
            }
        }
    }
});

// Completion Chart
const completionCtx = document.getElementById('completionChart').getContext('2d');
const completionChart = new Chart(completionCtx, {
    type: 'doughnut',
    data: {
        labels: ['Completed', 'In Progress', 'Not Started'],
        datasets: [{
            data: [65, 25, 10],
            backgroundColor: [
                '#00f7ff',
                '#b24bff',
                '#1a2332'
            ],
            borderColor: [
                '#00f7ff',
                '#b24bff',
                '#1a2332'
            ],
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    color: 'rgba(255, 255, 255, 0.7)',
                    padding: 15
                }
            }
        }
    }
});

// Performance Chart
const performanceCtx = document.getElementById('performanceChart').getContext('2d');
const performanceChart = new Chart(performanceCtx, {
    type: 'radar',
    data: {
        labels: ['Speed', 'Accuracy', 'Efficiency', 'Quality', 'Consistency'],
        datasets: [{
            label: 'Current',
            data: [85, 70, 75, 90, 65],
            backgroundColor: 'rgba(0, 247, 255, 0.2)',
            borderColor: '#00f7ff',
            borderWidth: 2,
            pointBackgroundColor: '#00f7ff'
        }, {
            label: 'Previous',
            data: [65, 60, 70, 75, 60],
            backgroundColor: 'rgba(255, 46, 136, 0.2)',
            borderColor: '#ff2e88',
            borderWidth: 2,
            pointBackgroundColor: '#ff2e88'
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            r: {
                angleLines: {
                    color: 'rgba(255, 255, 255, 0.1)'
                },
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)'
                },
                pointLabels: {
                    color: 'rgba(255, 255, 255, 0.7)'
                },
                ticks: {
                    color: 'rgba(255, 255, 255, 0.5)',
                    backdropColor: 'transparent'
                }
            }
        },
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    color: 'rgba(255, 255, 255, 0.7)',
                    padding: 15
                }
            }
        }
    }
});

// Growth Chart
const growthCtx = document.getElementById('growthChart').getContext('2d');
const growthChart = new Chart(growthCtx, {
    type: 'bar',
    data: {
        labels: ['Q1', 'Q2', 'Q3', 'Q4'],
        datasets: [{
            label: 'Growth',
            data: [35, 45, 60, 78],
            backgroundColor: [
                'rgba(0, 247, 255, 0.5)',
                'rgba(178, 75, 255, 0.5)',
                'rgba(255, 46, 136, 0.5)',
                'rgba(78, 204, 163, 0.5)'
            ],
            borderColor: [
                '#00f7ff',
                '#b24bff',
                '#ff2e88',
                '#4ecca3'
            ],
            borderWidth: 2,
            borderRadius: 5
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)'
                },
                ticks: {
                    color: 'rgba(255, 255, 255, 0.7)'
                }
            },
            x: {
                grid: {
                    display: false
                },
                ticks: {
                    color: 'rgba(255, 255, 255, 0.7)'
                }
            }
        },
        plugins: {
            legend: {
                display: false
            }
        }
    }
});