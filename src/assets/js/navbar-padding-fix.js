// Dynamically set body padding-top to navbar height
function updateBodyPaddingForNavbar() {
  var navbar = document.querySelector('.main-nav');
  if (navbar) {
    document.body.style.paddingTop = navbar.offsetHeight + 'px';
  }
}

document.addEventListener('DOMContentLoaded', updateBodyPaddingForNavbar);
window.addEventListener('resize', updateBodyPaddingForNavbar);
