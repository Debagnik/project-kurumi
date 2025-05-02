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
        commentBody.addEventListener('input', function () {
            document.getElementById('charCount').textContent = this.value.length;
        });
    }

    //Post Content Body TAB Behavior #107
    const textarea = document.getElementById('markdownbody');
    if (textarea) {
        textarea.addEventListener('keydown', function (e) {
            if (e.key === 'Tab') {
                e.preventDefault();

                const start = this.selectionStart;
                const end = this.selectionEnd;

                if (!e.shiftKey) {
                    // Insert 4 spaces at cursor position
                    const spaces = "    ";
                    this.value = this.value.substring(0, start) + spaces + this.value.substring(end);
                    // Move cursor
                    this.selectionStart = this.selectionEnd = start + spaces.length;
                } else {
                    const beforeCursor = this.value.substring(0, start);
                    const afterCursor = this.value.substring(end);

                    // Match the last group of 4+ spaces before cursor
                    const match = beforeCursor.match(/( {4,})$/);
                    if (match) {
                        const spacesToRemove = match[0].length >= 4 ? 4 : 0;
                        const newBefore = beforeCursor.slice(0, -spacesToRemove);
                        this.value = newBefore + afterCursor;
                        this.selectionStart = this.selectionEnd = start - spacesToRemove;
                    }
                }
            }
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

        generateButton.addEventListener('click', async function () {
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

    // Function to handle tag input restrictions and formatting
    function initializeTagInputs() {
        // Find all tag input fields across different pages
        const tagInputs = document.querySelectorAll('input[name="tags"]');
        
        tagInputs.forEach(input => {
            // Function to format tags properly
            function formatTags(value) {
                // Convert to lowercase
                let formatted = value.toLowerCase();
                
                // Only allow letters, numbers, hyphens, underscores, and commas
                formatted = formatted.replace(/[^a-z0-9\-_,\s]/g, '');
                
                // Split by comma, trim whitespace, and filter out empty tags
                let tags = formatted.split(',')
                    .map(tag => tag.trim())
                    .filter(tag => tag.length > 0);
                
                // Join back with ", " format
                return tags.join(', ');
            }

            // Show error message for capital letters
            function showError(input, message) {
                // Remove any existing error message
                const existingError = input.parentElement.querySelector('.tag-error');
                if (existingError) {
                    existingError.remove();
                }

                // Create and show new error message if there are capital letters
                if (/[A-Z]/.test(input.value)) {
                    const errorDiv = document.createElement('div');
                    errorDiv.className = 'tag-error';
                    errorDiv.style.color = 'var(--red)';
                    errorDiv.style.fontSize = '0.8rem';
                    errorDiv.style.marginTop = '0.25rem';
                    errorDiv.textContent = message;
                    input.parentElement.appendChild(errorDiv);
                }
            }

            // Handle input events to show error for capital letters
            input.addEventListener('input', function() {
                showError(this, 'Please use lowercase letters only');
            });

            // Format tags when input loses focus
            input.addEventListener('blur', function() {
                this.value = formatTags(this.value);
                // Remove error message after formatting
                const errorDiv = this.parentElement.querySelector('.tag-error');
                if (errorDiv) {
                    errorDiv.remove();
                }
            });
        });
    }

    // Initialize tag inputs when DOM is loaded
    initializeTagInputs();
});