const username = document.getElementById('username');
const password = document.getElementById('password');
const schedule = document.getElementById('ScheduleList');
const getBtn = document.getElementById('getScheduleBtn');
const signBtn = document.getElementById('SignInBtn');
const msg = document.getElementById('message');
const disclaimerTrigger = document.getElementById('disclaimerTrigger');
const disclaimerModal = document.getElementById('disclaimerModal');
const pausedModal = document.getElementById('pausedModal');

let publicKey = '';
let ticket = '';
let servicePaused = false;
let requestVersion = 0;
let querying = false;
let signing = false;
let messageTimer;

async function encryptPassword(value) {
    const encoded = publicKey.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const der = Uint8Array.from(atob(encoded), char => char.charCodeAt(0));
    const key = await crypto.subtle.importKey('spki', der, {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        },
        false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
            name: 'RSA-OAEP'
        }, key,
        new TextEncoder().encode(value)));
    return btoa(String.fromCharCode(...ciphertext));
}

async function fetchJson(url, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 60000);
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        const data = await response.json();
        if (!response.ok && !data.STATUS) throw new Error('服务请求失败');
        return data;
    } finally {
        clearTimeout(timer);
    }
}

function showMessage(text, type = 'success') {
    clearTimeout(messageTimer);
    msg.textContent = text;
    msg.className = `message ${type} show`;
    messageTimer = setTimeout(() => msg.classList.remove('show'), 5000);
}

function updateControls() {
    const busy = servicePaused || querying || signing;
    username.disabled = busy;
    password.disabled = busy;
    schedule.disabled = busy;
    getBtn.disabled = busy;
    getBtn.textContent = querying ? '查询中...' : '查询课程';
    signBtn.disabled = busy || !ticket || !schedule.value;
    signBtn.classList.toggle('active', !signBtn.disabled);
    signBtn.textContent = signing ? '签到中...' : '签到';
}

function resetAll() {
    requestVersion++;
    ticket = '';
    schedule.innerHTML = '<option value="" disabled selected class="placeholder">请先查询课程</option>';
    updateControls();
}

function openDisclaimer() {
    if (servicePaused) return;
    let dismissed = false;
    try {
        dismissed = localStorage.getItem('buaa_disclaimer_dismissed') === 'true';
    } catch (_) {
        /* storage unavailable */
    }
    document.getElementById('dontShowAgain').checked = dismissed;
    const trigger = disclaimerTrigger.getBoundingClientRect();
    const overlay = disclaimerModal.getBoundingClientRect();
    disclaimerModal.style.setProperty('--collapse-x', `${trigger.left + trigger.width / 2 - (overlay.left + overlay.width / 2)}px`);
    disclaimerModal.style.setProperty('--collapse-y', `${trigger.top + trigger.height / 2 - (overlay.top + overlay.height / 2)}px`);
    disclaimerModal.classList.add('show');
}

disclaimerTrigger.addEventListener('click', openDisclaimer);

try {
    if (localStorage.getItem('buaa_disclaimer_dismissed') !== 'true') {
        requestAnimationFrame(openDisclaimer);
    }
} catch (_) {
    requestAnimationFrame(openDisclaimer);
}

document.getElementById('disclaimerConfirm').addEventListener('click', () => {
    try {
        if (document.getElementById('dontShowAgain').checked) {
            localStorage.setItem('buaa_disclaimer_dismissed', 'true');
        } else {
            localStorage.removeItem('buaa_disclaimer_dismissed');
        }
    } catch (_) {
        /* storage unavailable */
    }
    disclaimerModal.classList.remove('show');
});

function setServicePaused(data) {
    servicePaused = true;
    disclaimerModal.classList.remove('show');
    const message = (data.paused_message || data.message || '服务器维护，暂停使用') +
        (data.resume_time ? `，预计 ${data.resume_time} 恢复` : '');
    document.body.classList.add('service-paused');
    const banner = document.getElementById('pausedBanner');
    banner.textContent = message;
    banner.classList.add('show');
    document.getElementById('pausedMessage').textContent = message;
    updateControls();
    disclaimerTrigger.disabled = true;
    pausedModal.classList.add('show');
}

document.getElementById('pausedConfirm').addEventListener('click', () => {
    pausedModal.classList.remove('show');
});

async function init() {
    showMessage('初始化成功', 'initialize');
    try {
        const data = await fetchJson('/api/config', {
            headers: {
                Accept: 'application/json'
            }
        });
        if (data.status === 'paused') {
            setServicePaused(data);
        } else if (!['healthy', 'unconfigured'].includes(data.status)) {
            showMessage('服务状态未知，请刷新页面重试', 'error');
        } else if (data.status === 'unconfigured' || !data.public_key) {
            showMessage('服务尚未完成配置', 'error');
        } else {
            publicKey = data.public_key;
        }
    } catch (error) {
        showMessage(error.name === 'AbortError' ? '服务状态获取超时，请刷新页面重试' : '服务状态获取失败，请刷新页面重试', 'error');
    }
}

getBtn.addEventListener('click', async () => {
    if (servicePaused || querying || signing) return;
    const id = username.value.trim();
    if (!id || (!ticket && !password.value)) return showMessage('请填写账号与密码', 'error');
    if (!publicKey) return showMessage('服务尚未就绪，请刷新页面重试', 'error');
    const version = ++requestVersion;
    querying = true;
    updateControls();

    const body = {
        username: id
    };
    try {
        if (ticket) {
            body.ticket = ticket;
        } else {
            try {
                body.password = await encryptPassword(password.value);
            } catch (_) {
                if (version === requestVersion) showMessage('密码加密失败', 'error');
                return;
            }
        }
        if (version !== requestVersion) return;
        const data = await fetchJson('/api/iClassSchedule', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        });
        if (version !== requestVersion) return;
        if (data.STATUS === '5') {
            setServicePaused(data);
            return;
        }
        if (data.STATUS !== '0') {
            resetAll();
            return showMessage(data.STATUS === '6' ? '会话已过期，请重新查询' : (data.message || '查询失败，请重试'), 'error');
        }
        ticket = data.ticket || '';
        schedule.innerHTML = '<option value="" disabled selected class="placeholder">请选择课程</option>';
        const list = data.result || [];
        list.forEach(item => {
            const begin = (item.classBeginTime || '').slice(11, 16);
            const end = (item.classEndTime || '').slice(11, 16);
            const status = item.signStatus === '1' ? '已签到' : '未签到';
            const option = document.createElement('option');
            option.value = String(item.id);
            option.textContent = `${begin}-${end}  ${item.courseName || ''}  ${item.classroomName || ''}  ${item.teacherName || ''}  [${status}]`;
            schedule.appendChild(option);
        });
        showMessage(list.length ? '课程查询成功' : '今天没有课程，无需签到');
    } catch (error) {
        if (version === requestVersion) {
            showMessage(error.name === 'AbortError' ? '课程查询超时，请重试' : '网络请求失败，请重试', 'error');
        }
    } finally {
        querying = false;
        updateControls();
    }
});

signBtn.addEventListener('click', async () => {
    if (servicePaused || querying || signing || !ticket || !schedule.value) return;
    const courseId = schedule.value;
    const option = schedule.options[schedule.selectedIndex];
    const version = requestVersion;
    signing = true;
    updateControls();
    try {
        const data = await fetchJson('/api/iClassSign', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ticket,
                id: courseId
            })
        });
        if (version !== requestVersion) return;
        if (data.STATUS === '5') {
            setServicePaused(data);
            return;
        }
        if (data.STATUS === '6') {
            resetAll();
            return showMessage('会话已过期，请重新查询', 'error');
        }
        if (data.STATUS === '0') {
            option.textContent = option.textContent.replace('[未签到]', '[已签到]');
            showMessage('签到成功');
        } else {
            showMessage(data.message || data.ERRMSG || '签到失败', 'error');
        }
    } catch (error) {
        if (version === requestVersion) {
            showMessage(error.name === 'AbortError' ? '签到请求超时，请先重新查询确认结果后重试' : '网络请求失败，请重新查询确认签到结果', 'error');
        }
    } finally {
        signing = false;
        updateControls();
    }
});

schedule.addEventListener('change', updateControls);
username.addEventListener('input', resetAll);
password.addEventListener('input', resetAll);
init();