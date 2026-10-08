// Shared Environmental Trend Analysis for admin_home and resident_home.
// Both pages plot the same /api/get_sensor_history series (logged ~once a
// minute by risk_monitor_loop) on 1 MIN / 15 MIN / 30 MIN / 1 HR, and both
// sample the latest /api/get_sensor_data reading on a wall-clock 5 SEC grid
// so the two dashboards stay in lockstep.

(function (global) {
    const INTERVALS_MS = [5000, 60000, 900000, 1800000, 3600000];
    const FIVE_SEC_MS = 5000;
    const VISIBLE_POINTS = 15;
    const STORAGE_KEY = 'aedospotTrendRangeMs';
    const HISTORY_POLL_MS = 15000;

    const CHART_COLORS = {
        temp: '#e67e22',
        hum: '#f1c40f',
        rain: '#3498db',
        ph: '#9b59b6',
        wind: '#2ecc71'
    };

    const chartHistories = {};
    let currentRangeMs = 900000;
    let lastReading = null;
    let trendChart = null;
    let initialized = false;
    let fiveSecTimer = null;
    let historyTimer = null;

    function emptyBuffer() {
        return { timestamps: [], labels: [], temp: [], hum: [], rain: [], ph: [], wind: [] };
    }

    function alignTime(t, ms) {
        return Math.floor(t / ms) * ms;
    }

    function msUntilNextBoundary(ms) {
        const rem = Date.now() % ms;
        return rem === 0 ? ms : ms - rem;
    }

    function formatLabel(t, intervalMs) {
        const d = t instanceof Date ? t : new Date(t);
        const hh = d.getHours() % 12 || 12;
        const mm = String(d.getMinutes()).padStart(2, '0');
        const ampm = d.getHours() >= 12 ? 'PM' : 'AM';
        if (intervalMs === FIVE_SEC_MS) {
            const ss = String(d.getSeconds()).padStart(2, '0');
            return hh + ':' + mm + ':' + ss + ' ' + ampm;
        }
        return hh + ':' + mm + ' ' + ampm;
    }

    function getChartThemeColors() {
        const isLight = document.body.classList.contains('light-theme');
        if (isLight) {
            return {
                text: '#000000',
                grid: 'rgba(0,0,0,0.08)',
                tooltipBackground: 'rgba(255,255,255,0.95)',
                tooltipBorder: 'rgba(0,0,0,0.15)',
                tooltipTitle: '#000000',
                tooltipBody: '#000000'
            };
        }
        return {
            text: 'rgba(232,245,238,0.75)',
            grid: 'rgba(255,255,255,0.05)',
            tooltipBackground: 'rgba(7,26,15,0.92)',
            tooltipBorder: 'rgba(46,204,113,0.25)',
            tooltipTitle: '#e8f5ee',
            tooltipBody: 'rgba(232,245,238,0.75)'
        };
    }

    function makeDataset(label, color, data) {
        return {
            label: label,
            data: data.slice(),
            borderColor: color,
            backgroundColor: color + '22',
            borderWidth: 2,
            pointRadius: 0,
            pointHoverRadius: 4,
            tension: 0.4,
            fill: true
        };
    }

    function readingAtOrBefore(readings, t) {
        let chosen = null;
        for (let i = 0; i < readings.length; i++) {
            const ts = Date.parse(readings[i].timestamp);
            if (isNaN(ts)) continue;
            if (ts <= t) chosen = readings[i];
            else break;
        }
        return chosen;
    }

    function toPlotValues(r) {
        if (!r) return null;
        if (r.temp !== undefined) {
            return { temp: r.temp, hum: r.hum, rain: r.rain, ph: r.ph, wind: r.wind };
        }
        return {
            temp: r.temperature,
            hum: r.humidity,
            rain: r.rainfall_mm,
            ph: r.ph_level,
            wind: r.wind_speed
        };
    }

    function pushSlot(h, ts, intervalMs, values) {
        h.timestamps.push(ts);
        h.labels.push(formatLabel(ts, intervalMs));
        h.temp.push(values.temp);
        h.hum.push(values.hum);
        h.rain.push(values.rain);
        h.ph.push(values.ph);
        h.wind.push(values.wind);
    }

    function fillBuffer(intervalMs, readings, fallback) {
        const h = emptyBuffer();
        const nowAligned = alignTime(Date.now(), intervalMs);
        for (let i = VISIBLE_POINTS - 1; i >= 0; i--) {
            const ts = nowAligned - i * intervalMs;
            const src = readingAtOrBefore(readings, ts) || fallback;
            const values = toPlotValues(src);
            if (!values) continue;
            pushSlot(h, ts, intervalMs, values);
        }
        return h;
    }

    function replaceBuffer(ms, next) {
        const h = chartHistories[ms];
        h.timestamps = next.timestamps;
        h.labels = next.labels;
        h.temp = next.temp;
        h.hum = next.hum;
        h.rain = next.rain;
        h.ph = next.ph;
        h.wind = next.wind;
    }

    function updateLastPoint(values) {
        INTERVALS_MS.forEach(function (ms) {
            const h = chartHistories[ms];
            const lastIdx = h.temp.length - 1;
            if (lastIdx < 0) return;
            h.temp[lastIdx] = values.temp;
            h.hum[lastIdx] = values.hum;
            h.rain[lastIdx] = values.rain;
            h.ph[lastIdx] = values.ph;
            h.wind[lastIdx] = values.wind;
        });
    }

    function appendFiveSecPoint(values) {
        const h = chartHistories[FIVE_SEC_MS];
        const ts = alignTime(Date.now(), FIVE_SEC_MS);
        const lastTs = h.timestamps.length ? h.timestamps[h.timestamps.length - 1] : 0;
        if (lastTs === ts) {
            h.temp[h.temp.length - 1] = values.temp;
            h.hum[h.hum.length - 1] = values.hum;
            h.rain[h.rain.length - 1] = values.rain;
            h.ph[h.ph.length - 1] = values.ph;
            h.wind[h.wind.length - 1] = values.wind;
            return;
        }
        if (h.labels.length >= VISIBLE_POINTS) {
            ['timestamps', 'labels', 'temp', 'hum', 'rain', 'ph', 'wind'].forEach(function (k) {
                h[k].shift();
            });
        }
        pushSlot(h, ts, FIVE_SEC_MS, values);
    }

    function seedFromLiveIfEmpty(values) {
        INTERVALS_MS.forEach(function (ms) {
            if (chartHistories[ms].temp.length > 0) return;
            replaceBuffer(ms, fillBuffer(ms, [], values));
        });
    }

    function updateTrendChart() {
        if (!trendChart) return;
        const win = chartHistories[currentRangeMs];
        if (!win) return;
        trendChart.data.labels = win.labels;
        trendChart.data.datasets[0].data = win.temp;
        trendChart.data.datasets[1].data = win.hum;
        trendChart.data.datasets[2].data = win.rain;
        trendChart.data.datasets[3].data = win.ph;
        trendChart.data.datasets[4].data = win.wind;
        trendChart.update('none');
    }

    function setChartDefaults() {
        const colors = getChartThemeColors();
        Chart.defaults.color = colors.text;
        Chart.defaults.borderColor = colors.grid;
    }

    function createChart() {
        const canvas = document.getElementById('trendChart');
        if (!canvas || !global.Chart) return;
        Chart.defaults.font.family = "'Inter', sans-serif";
        setChartDefaults();
        const colors = getChartThemeColors();
        const initial = chartHistories[currentRangeMs];
        trendChart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: {
                labels: initial.labels.slice(),
                datasets: [
                    makeDataset('Temperature (°C)', CHART_COLORS.temp, initial.temp),
                    makeDataset('Humidity (%)', CHART_COLORS.hum, initial.hum),
                    makeDataset('Rainfall (mm)', CHART_COLORS.rain, initial.rain),
                    makeDataset('pH', CHART_COLORS.ph, initial.ph),
                    makeDataset('Wind Speed (m/s)', CHART_COLORS.wind, initial.wind)
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 400 },
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                        labels: {
                            boxWidth: 12,
                            boxHeight: 3,
                            padding: 14,
                            color: colors.text,
                            font: { size: 10 },
                            usePointStyle: true,
                            pointStyle: 'line'
                        }
                    },
                    tooltip: {
                        backgroundColor: colors.tooltipBackground,
                        borderColor: colors.tooltipBorder,
                        borderWidth: 1,
                        titleColor: colors.tooltipTitle,
                        bodyColor: colors.tooltipBody,
                        padding: 10
                    }
                },
                scales: {
                    x: {
                        grid: { color: colors.grid },
                        ticks: {
                            color: colors.text,
                            autoSkip: false,
                            maxTicksLimit: VISIBLE_POINTS,
                            maxRotation: 45,
                            minRotation: 0,
                            font: { size: 9 }
                        }
                    },
                    y: {
                        grid: { color: colors.grid },
                        ticks: { color: colors.text, font: { size: 9 } }
                    }
                }
            }
        });
    }

    function markActiveTab(ms) {
        document.querySelectorAll('.chart-tab').forEach(function (b) {
            const isMatch = parseInt(b.dataset.rangeMs, 10) === ms;
            b.classList.toggle('active', isMatch);
            b.style.background = isMatch ? 'var(--green-glow)' : 'transparent';
            b.style.color = isMatch ? 'var(--green-bright)' : 'var(--text-muted-alt)';
            b.style.borderColor = isMatch ? 'rgba(46,204,113,0.3)' : 'var(--glass-border)';
        });
    }

    function setRange(ms) {
        if (INTERVALS_MS.indexOf(ms) === -1) ms = 900000;
        currentRangeMs = ms;
        try { localStorage.setItem(STORAGE_KEY, String(ms)); } catch (e) { /* ignore */ }
        markActiveTab(ms);
        updateTrendChart();
    }

    function bindTabs() {
        document.querySelectorAll('.chart-tab').forEach(function (btn) {
            btn.addEventListener('click', function () {
                setRange(parseInt(this.dataset.rangeMs, 10));
            });
        });
    }

    function restoreRange() {
        let saved = null;
        try { saved = parseInt(localStorage.getItem(STORAGE_KEY), 10); } catch (e) { saved = null; }
        const active = document.querySelector('.chart-tab.active');
        const fromDom = active ? parseInt(active.dataset.rangeMs, 10) : 900000;
        setRange(INTERVALS_MS.indexOf(saved) !== -1 ? saved : fromDom);
    }

    async function loadHistory() {
        try {
            const res = await fetch('/api/get_sensor_history', { credentials: 'include' });
            if (!res.ok) return;
            const data = await res.json();
            if (!data.success || !Array.isArray(data.readings)) return;
            const readings = data.readings;
            const fallback = lastReading;
            INTERVALS_MS.forEach(function (ms) {
                if (ms === FIVE_SEC_MS && chartHistories[ms].temp.length > 0) return;
                replaceBuffer(ms, fillBuffer(ms, readings, fallback));
            });
            if (lastReading) updateLastPoint(lastReading);
            updateTrendChart();
        } catch (e) {
            console.error('Failed to load shared sensor history:', e);
        }
    }

    function startFiveSecClock() {
        if (fiveSecTimer) clearInterval(fiveSecTimer);
        function tick() {
            if (!lastReading) return;
            appendFiveSecPoint(lastReading);
            if (currentRangeMs === FIVE_SEC_MS) updateTrendChart();
        }
        setTimeout(function () {
            tick();
            fiveSecTimer = setInterval(tick, FIVE_SEC_MS);
        }, msUntilNextBoundary(FIVE_SEC_MS));
    }

    function applyReading(reading) {
        const values = toPlotValues(reading);
        if (!values) return;
        lastReading = values;
        seedFromLiveIfEmpty(values);
        updateLastPoint(values);
        updateTrendChart();
    }

    function updateTheme() {
        if (!trendChart) return;
        const colors = getChartThemeColors();
        setChartDefaults();
        trendChart.options.plugins.legend.labels.color = colors.text;
        trendChart.options.plugins.tooltip.backgroundColor = colors.tooltipBackground;
        trendChart.options.plugins.tooltip.borderColor = colors.tooltipBorder;
        trendChart.options.plugins.tooltip.titleColor = colors.tooltipTitle;
        trendChart.options.plugins.tooltip.bodyColor = colors.tooltipBody;
        trendChart.options.scales.x.ticks.color = colors.text;
        trendChart.options.scales.x.grid.color = colors.grid;
        trendChart.options.scales.y.ticks.color = colors.text;
        trendChart.options.scales.y.grid.color = colors.grid;
        trendChart.update('none');
    }

    function init() {
        if (initialized) return;
        const canvas = document.getElementById('trendChart');
        if (!canvas) return;
        initialized = true;
        INTERVALS_MS.forEach(function (ms) {
            chartHistories[ms] = emptyBuffer();
        });
        createChart();
        bindTabs();
        restoreRange();
        startFiveSecClock();
        loadHistory();
        historyTimer = setInterval(loadHistory, HISTORY_POLL_MS);
    }

    global.AedospotTrendAnalysis = {
        init: init,
        applyReading: applyReading,
        updateTheme: updateTheme
    };
})(window);
