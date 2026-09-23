// SecureHub VAPT Training Lab - Client Scripts
document.addEventListener('DOMContentLoaded', function() {
    // Update file input label when file selected
    const fileInput = document.getElementById('file');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const fileName = e.target.files[0] ? e.target.files[0].name : 'No file selected';
            const fileHint = document.getElementById('file-selected-name');
            if (fileHint) {
                fileHint.textContent = 'Selected: ' + fileName;
            }
        });
    }

    // Auto-hide non-error alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-success, .alert-info');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            alert.style.transition = 'opacity 0.5s ease';
            alert.style.opacity = '0';
            setTimeout(function() {
                alert.remove();
            }, 500);
        }, 5000);
    });
});
