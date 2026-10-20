const username = document.getElementById('username');
const password = document.getElementById('password');
const schedule = document.getElementById('ScheduleList');
const getBtn = document.getElementById('getScheduleBtn');
const signBtn = document.getElementById('SignInBtn');
const msg = document.getElementById('message');
const details = document.getElementById('disclaimerDetails');
const disclaimerModal = document.getElementById('disclaimerModal');
const pausedModal = document.getElementById('pausedModal');

let publicKey = '';
let ticket = '';
let servicePaused = false;

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

function showMessage(text, type = 'success') {
    msg.textContent = text;
    msg.className = `message ${type} show`;
    setTimeout(() => msg.classList.remove('show'), 5000);
}

showMessage('初始化成功', 'initialize');

function resetAll() {
    ticket = '';
    schedule.innerHTML = '<option value="" disabled selected class="placeholder">请先查询课程</option>';
    signBtn.disabled = true;
    signBtn.classList.remove('active');
}

// The collapsed declaration remains on the page; clicking it opens the same dialog.
document.getElementById('disclaimerModalContent').innerHTML =
    details.querySelector('.collapse-content-inner').innerHTML;

function openDisclaimer() {
    if (servicePaused) return;
    document.getElementById('dontShowAgain').checked = (localStorage.getItem('buaa_disclaimer_dismissed') === 'true');
    const trigger = details.querySelector('summary').getBoundingClientRect();
    const overlay = disclaimerModal.getBoundingClientRect();
    disclaimerModal.style.setProperty('--collapse-x', `${trigger.left + trigger.width / 2 - (overlay.left + overlay.width / 2)}px`);
    disclaimerModal.style.setProperty('--collapse-y', `${trigger.top + trigger.height / 2 - (overlay.top + overlay.height / 2)}px`);
    disclaimerModal.classList.add('show');
}

details.querySelector('summary').addEventListener('click', event => {
    event.preventDefault();
    openDisclaimer();
});

try {
    if (localStorage.getItem('buaa_disclaimer_dismissed') !== 'true') {
        requestAnimationFrame(openDisclaimer);
    }
} catch (_) {
    requestAnimationFrame(openDisclaimer);
}

document.getElementById('disclaimerConfirm').addEventListener('click', () => {
    if (document.getElementById('dontShowAgain').checked) {
        try {
            localStorage.setItem('buaa_disclaimer_dismissed', 'true');
        } catch (_) {
            /* private mode */ }
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
    username.disabled = true;
    password.disabled = true;
    schedule.disabled = true;
    getBtn.disabled = true;
    signBtn.disabled = true;
    details.style.pointerEvents = 'none';
    pausedModal.classList.add('show');
}

document.getElementById('pausedConfirm').addEventListener('click', () => {
    pausedModal.classList.remove('show');
});

async function init() {
    try {
        const response = await fetch('/api/config', {
            headers: {
                Accept: 'application/json'
            }
        });
        const data = await response.json();
        publicKey = data.public_key || '';
        if (data.status === 'paused') setServicePaused(data);
        if (!servicePaused && !publicKey) showMessage('服务尚未完成密钥配置', 'error');
    } catch (_) {
        showMessage('服务状态获取失败', 'error');
    }
}

getBtn.addEventListener('click', async () => {
    if (servicePaused) return;
    const id = username.value.trim();
    if (!id || (!ticket && !password.value)) return showMessage('请填写账号与密码', 'error');
    if (!publicKey) return showMessage('服务尚未完成密钥配置', 'error');
    getBtn.disabled = true;
    getBtn.textContent = '查询中...';

    const body = {
        username: id
    };
    if (ticket) {
        body.ticket = ticket;
    } else {
        try {
            body.password = await encryptPassword(password.value);
        } catch (_) {
            getBtn.disabled = false;
            getBtn.textContent = '查询课程';
            return showMessage('密码加密失败', 'error');
        }
    }

    try {
        const response = await fetch('/api/iClassSchedule', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        });
        const data = await response.json();
        if (data.STATUS === '5') {
            setServicePaused(data);
            return;
        }
        if (data.STATUS !== '0') {
            if (ticket) ticket = '';
            return showMessage(data.message || '查询失败，请重试', 'error');
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
    } catch (_) {
        showMessage('网络请求失败', 'error');
    } finally {
        if (!servicePaused) {
            getBtn.disabled = false;
            getBtn.textContent = '查询课程';
        }
    }
});

signBtn.addEventListener('click', async () => {
    if (servicePaused || !ticket || !schedule.value) return;
    signBtn.disabled = true;
    signBtn.textContent = '签到中...';
    try {
        const response = await fetch('/api/iClassSign', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ticket,
                id: schedule.value
            })
        });
        const data = await response.json();
        if (data.STATUS === '5') {
            setServicePaused(data);
            return;
        }
        if (data.STATUS === '0') {
            const option = schedule.options[schedule.selectedIndex];
            option.textContent = option.textContent.replace('[未签到]', '[已签到]');
            showMessage('签到成功');
        } else {
            showMessage(data.message || data.ERRMSG || '签到失败', 'error');
        }
    } catch (_) {
        showMessage('网络请求失败', 'error');
    } finally {
        if (!servicePaused) {
            signBtn.disabled = !schedule.value;
            signBtn.textContent = '签到';
        }
    }
});

schedule.addEventListener('change', () => {
    signBtn.disabled = !schedule.value;
    signBtn.classList.toggle('active', !!schedule.value);
});
username.addEventListener('input', resetAll);
password.addEventListener('input', resetAll);
init();