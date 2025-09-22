// web_ui/static/js/main.js
document.addEventListener('DOMContentLoaded', () => {
    const profileSelect = document.getElementById('profile');
    if (profileSelect) {
        profileSelect.addEventListener('change', function() {
            const portsGroup = document.getElementById('ports-group');
            portsGroup.style.display = this.value === 'deep' ? 'block' : 'none';
        });
    }
});