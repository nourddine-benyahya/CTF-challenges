document.getElementById('btn').addEventListener('click', () => {
    const input = document.getElementById('input').value
        .replace(/[&*%]/g, '')
        .substring(0, 100);
        
    const frame = document.getElementById('frame');
    frame.src = `/frame.html?content=${encodeURIComponent(input)}`;
});