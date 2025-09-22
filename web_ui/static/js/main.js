// web_ui/static/js/main.js
document.addEventListener('DOMContentLoaded', () => {
    const profileSelect = document.getElementById('profile');
    if (profileSelect) {
        // Function to toggle port visibility
        const togglePorts = () => {
            const portsGroup = document.getElementById('ports-group');
            if (portsGroup) {
                 portsGroup.style.display = profileSelect.value === 'deep' ? 'block' : 'none';
            }
        };
        // Run on page load and on change
        togglePorts();
        profileSelect.addEventListener('change', togglePorts);
    }
});