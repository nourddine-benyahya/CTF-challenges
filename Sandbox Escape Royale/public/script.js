window.name = 'secureFrame';

const _0xdeadbeef = document.getElementById('btn');
_0xdeadbeef.addEventListener('click', () => {
    const _0xcafebabe = document.getElementById('input').value
        .replace(/[&*%]/g, '')
        .substring(0, 100);

    const _0xfeedface = document.getElementById('frame');
    _0xfeedface.src = `/frame.html?content=${btoa(encodeURIComponent(_0xcafebabe))}`;
});