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
});