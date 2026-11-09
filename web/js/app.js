document.addEventListener('DOMContentLoaded', () => {
    // Show who is logged in and wire the Logout button
    fetch('/api/v1/auth/me').then(r => r.ok ? r.json() : null).then(u => {
        if (u) document.getElementById('navUser').textContent = u.username;
    });
    document.getElementById('logoutBtn').addEventListener('click', async () => {
        await fetch('/api/v1/auth/logout', { method: 'POST' });
        window.location.href = '/login.html';
    });

    initTheme();
    initMobileMenu();
    initScrollSpy();
    initRevealAnimations();
    initTabs();
    initParticles();
    
    loadSamples();
    loadHistory();

    const scanBtn = document.getElementById('scanBtn');
    const urlInput = document.getElementById('urlInput');

    scanBtn.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (url) performScan(url);
    });

    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const url = urlInput.value.trim();
            if (url) performScan(url);
        }
    });
});

// --- Theme Management ---
function initTheme() {
    const toggleBtn = document.getElementById('themeToggle');
    const savedTheme = localStorage.getItem('phishguard-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    toggleBtn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('phishguard-theme', next);
        initParticles(); // Re-init particles with new colors
    });
}

// --- Mobile Menu ---
function initMobileMenu() {
    const btn = document.getElementById('mobileMenuBtn');
    const links = document.getElementById('navLinks');
    
    btn.addEventListener('click', () => {
        btn.classList.toggle('active');
        links.classList.toggle('active');
    });

    // Close on click
    links.querySelectorAll('a').forEach(a => {
        a.addEventListener('click', () => {
            btn.classList.remove('active');
            links.classList.remove('active');
        });
    });
}

// --- ScrollSpy & Sticky Nav ---
function initScrollSpy() {
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-links a');
    const header = document.getElementById('mainNav');

    window.addEventListener('scroll', () => {
        let current = '';
        const scrollY = window.pageYOffset;

        // Sticky Header
        if (scrollY > 50) {
            header.style.boxShadow = 'var(--shadow-sm)';
            header.style.background = 'var(--bg-secondary)';
        } else {
            header.style.boxShadow = 'none';
        }

        sections.forEach(section => {
            const sectionTop = section.offsetTop - 100;
            const sectionHeight = section.clientHeight;
            if (scrollY >= sectionTop && scrollY < sectionTop + sectionHeight) {
                current = section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${current}`) {
                link.classList.add('active');
            }
        });
    });
}

// --- Reveal Animations on Scroll ---
function initRevealAnimations() {
    const reveals = document.querySelectorAll('.reveal');
    const counters = document.querySelectorAll('.counter');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
                
                // If it's a counter, animate it
                if (entry.target.classList.contains('stats-grid')) {
                    animateCounters();
                }
                
                // Optional: Stop observing once revealed
                // observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    reveals.forEach(reveal => {
        observer.observe(reveal);
    });
}

// --- Counter Animation ---
let countersAnimated = false;
function animateCounters() {
    if (countersAnimated) return;
    countersAnimated = true;

    const counters = document.querySelectorAll('.counter');
    const speed = 200; // lower = faster

    counters.forEach(counter => {
        const updateCount = () => {
            const target = +counter.getAttribute('data-target');
            const count = +counter.innerText;
            const inc = target / speed;

            if (count < target) {
                counter.innerText = Math.ceil(count + inc);
                setTimeout(updateCount, 15);
            } else {
                counter.innerText = target;
            }
        };
        updateCount();
    });
}

// --- Tabs ---
function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            const target = btn.getAttribute('data-tab');
            document.getElementById(target).classList.add('active');
        });
    });
}

// --- API Interactions ---
async function loadSamples() {
    try {
        const res = await fetch('/api/v1/samples');
        if (!res.ok) return;
        const samples = await res.json();
        const container = document.getElementById('samplePills');
        container.innerHTML = '<span class="sample-pill-label">Quick Test:</span>';

        samples.forEach(s => {
            const pill = document.createElement('button');
            pill.className = 'sample-pill';
            pill.innerText = s.name;
            pill.onclick = () => {
                document.getElementById('urlInput').value = s.url;
                performScan(s.url);
            };
            container.appendChild(pill);
        });
    } catch (e) {
        console.error('Failed to load sample targets:', e);
    }
}

async function performScan(url) {
    const scanBtn = document.getElementById('scanBtn');
    const resultsContainer = document.getElementById('resultsContainer');
    const progress = document.getElementById('scanProgress');
    const progressBar = document.getElementById('scanProgressBar');
    const progressText = document.getElementById('scanProgressText');
    
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><span>Scanning...</span>';
    
    progress.classList.add('active');
    
    // Simulate scan phases
    let progressVal = 0;
    const interval = setInterval(() => {
        progressVal += 5;
        if(progressVal > 90) progressVal = 90;
        progressBar.style.width = `${progressVal}%`;
        
        if (progressVal < 30) progressText.innerText = "Analyzing URL structure & domains...";
        else if (progressVal < 60) progressText.innerText = "Fetching DOM & evaluating resources...";
        else progressText.innerText = "Running threat classification heuristics...";
    }, 200);

    try {
        const res = await fetch('/api/v1/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        clearInterval(interval);
        progressBar.style.width = '100%';
        progressText.innerText = "Scan complete!";

        if (res.status === 401) { window.location.href = '/login.html'; return; }
        if (!res.ok) {
            const err = await res.json();
            showToast('Scan Error', err.error || 'Failed to scan target URL', 'error');
            return;
        }

        const data = await res.json();
        setTimeout(() => {
            progress.classList.remove('active');
            renderResults(data);
            loadHistory();
            
            // Scroll to results
            resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 500);

    } catch (e) {
        clearInterval(interval);
        showToast('Network Error', e.message, 'error');
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span>Scan Website</span>';
    }
}

function renderResults(data) {
    const resultsContainer = document.getElementById('resultsContainer');
    resultsContainer.classList.add('visible');

    // Update Score & Gauge
    const scoreVal = data.riskScore;
    document.getElementById('scoreDisplay').innerText = scoreVal + '%';
    updateGauge(scoreVal);

    // Update Badge
    const badge = document.getElementById('riskBadge');
    badge.className = 'badge-risk';
    if (data.riskLevel === 'PHISHING') {
        badge.classList.add('badge-phishing');
        badge.innerText = 'High Risk Phishing';
    } else if (data.riskLevel === 'SUSPICIOUS') {
        badge.classList.add('badge-suspicious');
        badge.innerText = 'Suspicious Website';
    } else {
        badge.classList.add('badge-safe');
        badge.innerText = 'Safe / Benign';
    }

    // Update Attack Type Banner
    document.getElementById('attackTypeName').innerText = data.attackType ? data.attackType.displayName : 'General Analysis';
    document.getElementById('attackTypeDesc').innerText = data.attackType ? data.attackType.description : '';

    // Update Summary
    document.getElementById('userSummaryText').innerText = data.userSummary;

    // Render Risk Factors
    const factorsList = document.getElementById('factorsList');
    factorsList.innerHTML = '';
    
    if (data.riskFactors && data.riskFactors.length > 0) {
        data.riskFactors.forEach(rf => {
            const div = document.createElement('div');
            div.className = 'factor-item reveal';
            
            const sevClass = 'impact-' + (rf.severity ? rf.severity.toLowerCase() : 'low');
            div.innerHTML = `
                <div class="factor-header">
                    <span class="factor-title">${escapeHtml(rf.title)}</span>
                    <span class="factor-impact ${sevClass}">+${rf.scoreImpact}% Risk</span>
                </div>
                <div class="factor-desc">${escapeHtml(rf.description)}</div>
                <div class="factor-rec">💡 ${escapeHtml(rf.recommendation)}</div>
            `;
            factorsList.appendChild(div);
        });
        
        // Trigger reveal for new items
        setTimeout(() => {
            document.querySelectorAll('.factor-item').forEach((el, i) => {
                setTimeout(() => el.classList.add('active'), i * 100);
            });
        }, 100);
    } else {
        factorsList.innerHTML = '<div class="empty-state"><div class="empty-state-icon">✅</div><div class="empty-state-text">No security risk factors detected. Website exhibits clean behavior.</div></div>';
    }

    // Render Technical Details
    document.getElementById('techDetailsBox').innerText = data.technicalDetails;
}

function updateGauge(score) {
    const needle = document.getElementById('gaugeNeedle');
    // The needle line points left at 0 degrees: turn clockwise 0 (0%) to 180 (100%)
    const angle = (score / 100) * 180;
    needle.setAttribute('transform', `rotate(${angle}, 120, 115)`);
    // Fill the coloured arc in proportion to the score (arc length is about 298)
    const arc = document.getElementById('gaugeArc');
    if (arc) arc.style.strokeDashoffset = 298 * (1 - score / 100);
}

async function loadHistory() {
    try {
        const res = await fetch('/api/v1/history');
        if (!res.ok) return;
        const history = await res.json();
        const tbody = document.getElementById('historyTbody');
        tbody.innerHTML = '';
        
        // Update counters
        document.getElementById('totalScans').setAttribute('data-target', history.length);
        
        let phishingCount = 0;
        let safeCount = 0;
        let totalScore = 0;

        if (history.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No scans performed yet.</td></tr>';
            return;
        }

        history.forEach(h => {
            if (h.riskLevel === 'PHISHING' || h.riskLevel === 'SUSPICIOUS') phishingCount++;
            if (h.riskLevel === 'SAFE') safeCount++;
            totalScore += h.riskScore;

            const tr = document.createElement('tr');
            const badgeClass = h.riskLevel === 'PHISHING' ? 'badge-phishing' : (h.riskLevel === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-safe');
            tr.innerHTML = `
                <td style="font-family: monospace; color: var(--text-muted);">${escapeHtml(h.scanId)}</td>
                <td><a href="#" onclick="event.preventDefault(); document.getElementById('urlInput').value='${escapeHtml(h.targetUrl)}'; performScan('${escapeHtml(h.targetUrl)}');">${escapeHtml(h.targetUrl)}</a></td>
                <td><span class="badge-risk ${badgeClass}" style="padding: 4px 12px; font-size: 11px;">${h.riskScore}%</span></td>
                <td>${escapeHtml(h.attackType ? h.attackType.displayName : 'Analysis')}</td>
                <td style="color: var(--text-muted); font-size: 13px;">${escapeHtml(h.timestamp)}</td>
            `;
            tbody.appendChild(tr);
        });

        // Update other stats
        document.getElementById('threatsDetected').setAttribute('data-target', phishingCount);
        document.getElementById('safeVerified').setAttribute('data-target', safeCount);
        document.getElementById('avgRisk').setAttribute('data-target', Math.round(totalScore / history.length));
        
        countersAnimated = false; // allow re-animation if in view
        animateCounters();

    } catch (e) {
        console.error('Failed to load scan history:', e);
    }
}

// --- Utils ---
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function showToast(title, message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <div style="flex:1;">
            <strong>${title}</strong>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">${message}</div>
        </div>
    `;
    container.appendChild(toast);
    
    // Animate in
    requestAnimationFrame(() => toast.classList.add('show'));
    
    // Remove after 3s
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// --- Background Particles ---
function initParticles() {
    const canvas = document.getElementById('particleCanvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const pColor = isDark ? 'rgba(20, 184, 166, 0.2)' : 'rgba(13, 148, 136, 0.2)';
    
    let particles = [];
    for(let i=0; i<50; i++) {
        particles.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            r: Math.random() * 2 + 1,
            dx: (Math.random() - 0.5) * 0.5,
            dy: (Math.random() - 0.5) * 0.5
        });
    }
    
    function animate() {
        requestAnimationFrame(animate);
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        particles.forEach(p => {
            p.x += p.dx;
            p.y += p.dy;
            
            if(p.x < 0 || p.x > canvas.width) p.dx = -p.dx;
            if(p.y < 0 || p.y > canvas.height) p.dy = -p.dy;
            
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = pColor;
            ctx.fill();
        });
    }
    
    animate();
    
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// Spin animation css inject
const style = document.createElement('style');
style.textContent = `
    @keyframes spin { 100% { transform: rotate(360deg); } }
    .spin { animation: spin 1s linear infinite; }
`;
document.head.appendChild(style);
