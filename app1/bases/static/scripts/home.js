
        document.addEventListener('DOMContentLoaded', () => {
            // Theme initialization
            const savedTheme = localStorage.getItem('theme') || 'dark';
            const themeIcon = document.querySelector('.theme-toggle i');

            document.documentElement.setAttribute('data-theme', savedTheme);
            if (savedTheme === 'light') {
                themeIcon.classList.remove('fa-moon');
                themeIcon.classList.add('fa-sun');
            }

            // Animate statistics numbers
            const stats = document.querySelectorAll('.stat-number');
            stats.forEach(stat => {
                const target = parseInt(stat.getAttribute('data-target'));
                const increment = target / 200;

                function updateCount() {
                    const current = parseInt(stat.innerText);
                    if (current < target) {
                        stat.innerText = Math.ceil(current + increment);
                        setTimeout(updateCount, 10);
                    } else {
                        stat.innerText = target.toLocaleString();
                    }
                }
                updateCount();
            });

            // Feature card hover effects
            const featureCards = document.querySelectorAll('.feature-card');
            featureCards.forEach(card => {
                card.addEventListener('mouseenter', () => {
                    card.style.transform = 'translateY(-10px)';
                });

                card.addEventListener('mouseleave', () => {
                    card.style.transform = 'translateY(0)';
                });
            });

            // Mini Charts Initialization
            // Mini Growth Chart
            const growthCtx = document.getElementById('miniGrowthChart');
            if (growthCtx) {
                new Chart(growthCtx, {
                    type: 'line',
                    data: {
                        labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
                        datasets: [{
                            data: [30, 45, 35, 50, 45],
                            borderColor: '#00f7ff',
                            backgroundColor: 'rgba(0, 247, 255, 0.1)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2,
                            pointRadius: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: {
                                display: false,
                                beginAtZero: true
                            },
                            x: {
                                display: false
                            }
                        }
                    }
                });
            }

            // Mini User Activity Chart
            const userCtx = document.getElementById('miniUserChart');
            if (userCtx) {
                new Chart(userCtx, {
                    type: 'doughnut',
                    data: {
                        datasets: [{
                            data: [65, 35],
                            backgroundColor: ['#00f7ff', 'rgba(255, 255, 255, 0.1)'],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }
                        },
                        cutout: '80%'
                    }
                });
            }

            // Mini Success Rate Chart
            const successCtx = document.getElementById('miniSuccessChart');
            if (successCtx) {
                new Chart(successCtx, {
                    type: 'bar',
                    data: {
                        labels: ['M', 'T', 'W', 'T', 'F'],
                        datasets: [{
                            data: [85, 90, 88, 95, 92],
                            backgroundColor: '#b24bff',
                            borderRadius: 4,
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: {
                                display: false,
                                beginAtZero: true
                            },
                            x: {
                                display: false
                            }
                        }
                    }
                });
            }
        });

        // Theme toggle function
        function toggleTheme() {
            const html = document.documentElement;
            const themeIcon = document.querySelector('.theme-toggle i');

            if (html.getAttribute('data-theme') === 'dark') {
                html.setAttribute('data-theme', 'light');
                themeIcon.classList.remove('fa-moon');
                themeIcon.classList.add('fa-sun');
                localStorage.setItem('theme', 'light');
            } else {
                html.setAttribute('data-theme', 'dark');
                themeIcon.classList.remove('fa-sun');
                themeIcon.classList.add('fa-moon');
                localStorage.setItem('theme', 'dark');
            }
        }

        // Menu toggle function
        function toggleMenu() {
            const navLinks = document.querySelector('.nav-links');
            navLinks.classList.toggle('active');
        }
