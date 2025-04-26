document.addEventListener('DOMContentLoaded', function () {
    // Search functionality
    const allButtons = document.querySelectorAll('.searchBtn');
    const searchBar = document.querySelector('.searchBar');
    const searchInput = document.getElementById('searchInput');
    const searchClose = document.getElementById('searchClose');

    if (searchBar && searchInput && searchClose) {
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
    }

    // Escape key handler
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && searchBar && searchBar.classList.contains('open')) {
            searchClose.click();
        }
    });

    // Flash messages
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(msg => {
        setTimeout(() => {
            msg.classList.add('hide');
            setTimeout(() => {
                msg.style.display = 'none';
            }, 500);
        }, 5000);
    });

    const closeButtons = document.querySelectorAll('.flash-message .close-btn');
    closeButtons.forEach(button => {
        button.addEventListener('click', () => {
            const flashMessage = button.closest('.flash-message');
            flashMessage.classList.add('hide');
            setTimeout(() => {
                flashMessage.style.display = 'none';
            }, 500);
        });
    });

    // Comment character count
    const commentBody = document.getElementById('commentBody');
    if (commentBody) {
        commentBody.addEventListener('input', function() {
            document.getElementById('charCount').textContent = this.value.length;
        });
    }

    // Generate Summary functionality
    const generateButton = document.getElementById('generateSummaryBtn');
    if (generateButton) {
        const buttonText = generateButton.querySelector('.button-text');
        const spinner = generateButton.querySelector('.spinner');
        
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

        generateButton.addEventListener('click', async function() {
            console.log('Generate Summary clicked');
            setLoading(true);

            const formData = {
                title: document.getElementById('title').value,
                thumbnailImageURI: document.getElementById('thumbnailImageURI').value,
                markdownbody: document.getElementById('markdownbody').value,
                tags: document.getElementById('tags').value,
                _csrf: document.querySelector('input[name="_csrf"]').value
            };

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
                
                if (data.code === 200) {
                    document.getElementById('desc').value = data.message;
                } else {
                    alert('Error generating summary: ' + data.message);
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Error generating summary: ' + error.message);
            } finally {
                setLoading(false);
            }
        });
    }
});