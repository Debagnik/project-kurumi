document.addEventListener('DOMContentLoaded', function () {

    const allButtons = document.querySelectorAll('.searchBtn');
    const searchBar = document.querySelector('.searchBar');
    const searchInput = document.getElementById('searchInput');
    const searchClose = document.getElementById('searchClose');

    if (!searchBar || !searchInput || !searchClose) {
        console.error("Required elements not found! Don't make me point out such obvious things!");
        return;
    }

    for (var i = 0; i < allButtons.length; i++) {
        allButtons[i].addEventListener('click', function () {
            searchBar.style.visibility = 'visible';
            searchBar.classList.add('open');
            this.setAttribute('aria-expanded', 'true');
            searchInput.focus();
            searchInput.value = '';
        });
    }

    searchClose.addEventListener('click', function () {
        searchBar.style.visibility = 'hidden';
        searchBar.classList.remove('open');
        this.setAttribute('aria-expanded', 'false');
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && searchBar.classList.contains('open')) {
            searchClose.click();
        }
    });

    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(msg => {
        setTimeout(() => {
            msg.classList.add('hide');
            setTimeout(() => {
                msg.style.display = 'none';
            }, 500); // Match with the CSS transition
        }, 5000); // Auto-hide after 5 seconds
    });

    const closeButtons = document.querySelectorAll('.flash-message .close-btn');
    closeButtons.forEach(button => {
        button.addEventListener('click', () => {
            const flashMessage = button.closest('.flash-message');
            flashMessage.classList.add('hide');
            setTimeout(() => {
                flashMessage.style.display = 'none';
            }, 500); // Match transition time in CSS
        });
    });

    document.getElementById('commentBody').addEventListener('input', function() {
        document.getElementById('charCount').textContent = this.value.length;
    });

    // Wait for DOM to be ready
    document.addEventListener('DOMContentLoaded', function() {
        console.log('Script loaded');
        
        // Get the generate summary button and its elements
        const generateButton = document.getElementById('generateSummaryBtn');
        if (!generateButton) return;

        const buttonText = generateButton.querySelector('.button-text');
        const spinner = generateButton.querySelector('.spinner');
        
        // Function to set loading state
        function setLoading(isLoading) {
            if (isLoading) {
                generateButton.disabled = true;
                buttonText.textContent = 'Generating...';
                spinner.style.display = 'inline-block';
            } else {
                generateButton.disabled = false;
                buttonText.textContent = 'Generate Summary (Beta)';
                spinner.style.display = 'none';
            }
        }

        // Add click event listener
        generateButton.addEventListener('click', async function() {
            console.log('Generate Summary clicked');
            
            // Show loading state
            setLoading(true);

            const formData = {
                title: document.getElementById('title').value,
                thumbnailImageURI: document.getElementById('thumbnailImageURI').value,
                markdownbody: document.getElementById('markdownbody').value,
                tags: document.getElementById('tags').value,
                _csrf: document.querySelector('input[name="_csrf"]').value
            };

            console.log('Form data:', formData);

            try {
                const response = await fetch('/admin/generate-post-summary', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': formData._csrf
                    },
                    body: JSON.stringify(formData)
                });

                const data = await response.json();
                console.log('API response:', data);
                
                if (data.code === 200) {
                    document.getElementById('desc').value = data.message;
                } else {
                    alert('Error generating summary: ' + data.message);
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Error generating summary: ' + error.message);
            } finally {
                // Hide loading state
                setLoading(false);
            }
        });
    });
});